"""External validation on known AWS IAM privilege-escalation techniques.

The synthetic training data comes from our own generator, so accuracy on it
can't show that IAM-XAI recognizes attacks *documented by others*. This
benchmark encodes, as IAM-XAI scenarios, independently published attack
techniques:

- the 21 IAM privilege-escalation methods catalogued by Rhino Security Labs
  ("AWS IAM Privilege Escalation - Methods and Mitigation", 2018);
- five scenarios modelled on the public descriptions of Rhino's CloudGoat
  training environments and on well-known trust misconfigurations
  (the configurations are re-created from the descriptions, not copied);
- six benign negative controls that should *not* be flagged.

Each scenario runs through the unchanged pipeline (Phases 1-6). A scenario
counts as detected when some discovered attack path is rated HIGH or CRITICAL.
We report this for the Random Forest, the hybrid (RF + escalation floor) and
the static CLAUDE.md 5.4 rules, plus whether any attack path was found at all.

Usage::

    python -m experiments.benchmark
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd

from dataset.generator import discover_paths
from dataset.row_builder import build_feature_row, context_from_scenario
from graph.graph_builder import build_attack_graph
from models.baselines import apply_escalation_floor, predict_rule_based
from models.predict import MODELS_DIR, _load_available_models, predict_frame
from parser.normalizer import normalize_scenario

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "benchmark_results.json"
REPORT_PATH = OUTPUT_PATH.with_suffix(".md")
ACCOUNT = "123456789012"
SEVERE = {"HIGH", "CRITICAL"}
ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

ADMIN_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/AdminRole"
ADMIN_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/AdminPolicy"
ADMIN_USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/AdminUser"
ADMIN_GROUP_ARN = f"arn:aws:iam::{ACCOUNT}:group/Admins"
DEV_ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/DevRole"


def _allow(action: Any, resource: Any = "*", condition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Action": action, "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return stmt


def _trust(principal: Any, condition: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _admin_role(service: str) -> Dict[str, Any]:
    return {"name": "AdminRole", "trust_policy": _trust({"Service": service}), "permissions": [_allow("*")]}


_ADMIN_POLICY = {"name": "AdminPolicy", "type": "iam_policy", "arn": ADMIN_POLICY_ARN}
_CUSTOMER_SECRET = {
    "name": "CustomerSecret",
    "type": "secretsmanager",
    "arn": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:prod/customers",
    "tags": {"DataClassification": "restricted"},
}


def _attacker_scenario(sid: str, permissions: List[Dict[str, Any]], roles: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "scenario_id": sid,
        "users": [{"name": "Attacker", "permissions": permissions}, {"name": "AdminUser"}],
        "roles": roles or [],
        "resources": [_ADMIN_POLICY, _CUSTOMER_SECRET],
    }


def rhino_techniques() -> List[Dict[str, Any]]:
    """The 21 Rhino Security Labs IAM privilege-escalation methods."""
    dev_role = {"name": "DevRole", "trust_policy": _trust({"AWS": "Attacker"}), "permissions": [_allow("s3:GetObject", "arn:aws:s3:::dev-bucket/*")]}
    t = [
        ("R01", "iam:CreatePolicyVersion", [_allow("iam:CreatePolicyVersion", ADMIN_POLICY_ARN)], None),
        ("R02", "iam:SetDefaultPolicyVersion", [_allow("iam:SetDefaultPolicyVersion", ADMIN_POLICY_ARN)], None),
        ("R03", "iam:PassRole + ec2:RunInstances", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow("ec2:RunInstances")], [_admin_role("ec2.amazonaws.com")]),
        ("R04", "iam:CreateAccessKey (other user)", [_allow("iam:CreateAccessKey", ADMIN_USER_ARN)], None),
        ("R05", "iam:CreateLoginProfile", [_allow("iam:CreateLoginProfile", ADMIN_USER_ARN)], None),
        ("R06", "iam:UpdateLoginProfile", [_allow("iam:UpdateLoginProfile", ADMIN_USER_ARN)], None),
        ("R07", "iam:AttachUserPolicy", [_allow("iam:AttachUserPolicy", f"arn:aws:iam::{ACCOUNT}:user/Attacker")], None),
        ("R08", "iam:AttachGroupPolicy", [_allow("iam:AttachGroupPolicy", ADMIN_GROUP_ARN)], None),
        ("R09", "iam:AttachRolePolicy + sts:AssumeRole", [_allow("iam:AttachRolePolicy", DEV_ROLE_ARN)], [dev_role]),
        ("R10", "iam:PutUserPolicy", [_allow("iam:PutUserPolicy", f"arn:aws:iam::{ACCOUNT}:user/Attacker")], None),
        ("R11", "iam:PutGroupPolicy", [_allow("iam:PutGroupPolicy", ADMIN_GROUP_ARN)], None),
        ("R12", "iam:PutRolePolicy + sts:AssumeRole", [_allow("iam:PutRolePolicy", DEV_ROLE_ARN)], [dev_role]),
        ("R13", "iam:AddUserToGroup", [_allow("iam:AddUserToGroup", ADMIN_GROUP_ARN)], None),
        ("R14", "iam:UpdateAssumeRolePolicy + sts:AssumeRole", [_allow(["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], ADMIN_ROLE_ARN)], [_admin_role("ec2.amazonaws.com")]),
        ("R15", "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow(["lambda:CreateFunction", "lambda:InvokeFunction"])], [_admin_role("lambda.amazonaws.com")]),
        ("R16", "iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow(["lambda:CreateFunction", "lambda:CreateEventSourceMapping"])], [_admin_role("lambda.amazonaws.com")]),
        ("R17", "lambda:UpdateFunctionCode (privileged function)", [_allow("lambda:UpdateFunctionCode", f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:AdminTask")], [_admin_role("lambda.amazonaws.com")]),
        ("R18", "iam:PassRole + glue:CreateDevEndpoint", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow("glue:CreateDevEndpoint")], [_admin_role("glue.amazonaws.com")]),
        ("R19", "glue:UpdateDevEndpoint", [_allow("glue:UpdateDevEndpoint", f"arn:aws:glue:us-east-1:{ACCOUNT}:devEndpoint/*")], [_admin_role("glue.amazonaws.com")]),
        ("R20", "iam:PassRole + cloudformation:CreateStack", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow("cloudformation:CreateStack")], [_admin_role("cloudformation.amazonaws.com")]),
        ("R21", "iam:PassRole + datapipeline:CreatePipeline", [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow(["datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"])], [_admin_role("datapipeline.amazonaws.com")]),
    ]
    scenarios = []
    for sid, name, perms, roles in t:
        raw = _attacker_scenario(f"bench_{sid.lower()}", perms, roles)
        if sid == "R17":
            raw["resources"].append({"name": "AdminTask", "type": "lambda", "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:AdminTask"})
        scenarios.append({"id": sid, "name": name, "group": "Rhino IAM privilege escalation", "expected": "attack", "scenario": raw})
    return scenarios


def modelled_scenarios() -> List[Dict[str, Any]]:
    """Scenarios modelled on CloudGoat descriptions and well-known trust misconfigurations."""
    return [
        {
            "id": "C01", "name": "Policy version rollback (cf. CloudGoat iam_privesc_by_rollback)", "expected": "attack",
            "scenario": _attacker_scenario("bench_c01", [_allow(["iam:ListPolicyVersions", "iam:SetDefaultPolicyVersion"], ADMIN_POLICY_ARN)]),
        },
        {
            "id": "C02", "name": "Assume manager role, pass admin role to Lambda (cf. CloudGoat lambda_privesc)", "expected": "attack",
            "scenario": {
                "scenario_id": "bench_c02",
                "users": [{"name": "Chris"}],
                "roles": [
                    {"name": "LambdaManager", "trust_policy": _trust({"AWS": "Chris"}),
                     "permissions": [_allow("iam:PassRole", ADMIN_ROLE_ARN), _allow(["lambda:CreateFunction", "lambda:InvokeFunction"])]},
                    _admin_role("lambda.amazonaws.com"),
                ],
                "resources": [_CUSTOMER_SECRET],
            },
        },
        {
            "id": "C03", "name": "Pass admin role to an EC2 instance profile (cf. CloudGoat iam_privesc_by_attachment)", "expected": "attack",
            "scenario": _attacker_scenario(
                "bench_c03",
                [_allow(["iam:AddRoleToInstanceProfile", "iam:PassRole"], ADMIN_ROLE_ARN), _allow("ec2:RunInstances")],
                [_admin_role("ec2.amazonaws.com")],
            ),
        },
        {
            "id": "C04", "name": "Cross-account trust without ExternalId to restricted data (confused deputy)", "expected": "attack",
            "scenario": {
                "scenario_id": "bench_c04",
                "users": [],
                "roles": [{"name": "VendorAccess", "trust_policy": _trust({"AWS": "210987654321"}),
                           "permissions": [_allow("secretsmanager:GetSecretValue", _CUSTOMER_SECRET["arn"])]}],
                "resources": [_CUSTOMER_SECRET],
            },
        },
        {
            "id": "C05", "name": "Role assumable by any principal, reads restricted bucket", "expected": "attack",
            "scenario": {
                "scenario_id": "bench_c05",
                "users": [{"name": "Contractor"}],
                "roles": [{"name": "OpenRole", "trust_policy": _trust("*"),
                           "permissions": [_allow("s3:GetObject", "arn:aws:s3:::payroll-exports/*")]}],
                "resources": [{"name": "PayrollExports", "type": "s3", "arn": "arn:aws:s3:::payroll-exports",
                               "tags": {"DataClassification": "restricted"}}],
            },
        },
    ]


def negative_controls() -> List[Dict[str, Any]]:
    """Benign, least-privilege configurations that should be rated LOW/MEDIUM."""
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    public_bucket = {"name": "PublicAssets", "type": "s3", "arn": "arn:aws:s3:::public-assets", "tags": {"DataClassification": "public"}}
    internal_table = {"name": "Inventory", "type": "dynamodb", "arn": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/Inventory",
                      "tags": {"DataClassification": "internal"}}
    public_fn = {"name": "Thumbnailer", "type": "lambda", "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:Thumbnailer",
                 "tags": {"DataClassification": "public"}}

    def via_role(sid, perms, resources, condition=None):
        return {"scenario_id": sid, "users": [{"name": "Dev"}],
                "roles": [{"name": "ReadRole", "trust_policy": _trust({"AWS": "Dev"}, condition), "permissions": perms}],
                "resources": resources}

    return [
        {"id": "N01", "name": "MFA-gated role reads public assets", "expected": "benign",
         "scenario": via_role("bench_n01", [_allow("s3:GetObject", "arn:aws:s3:::public-assets/img/logo.png")], [public_bucket], mfa)},
        {"id": "N02", "name": "User reads internal inventory table", "expected": "benign",
         "scenario": {"scenario_id": "bench_n02", "users": [{"name": "Analyst", "permissions": [_allow("dynamodb:GetItem", internal_table["arn"])]}],
                      "roles": [], "resources": [internal_table]}},
        {"id": "N03", "name": "Role reads public Lambda configuration", "expected": "benign",
         "scenario": via_role("bench_n03", [_allow("lambda:GetFunction", public_fn["arn"])], [public_fn])},
        {"id": "N04", "name": "Role lists public bucket", "expected": "benign",
         "scenario": via_role("bench_n04", [_allow("s3:ListBucket", public_bucket["arn"])], [public_bucket])},
        {"id": "N05", "name": "Source-IP restricted role queries internal table", "expected": "benign",
         "scenario": via_role("bench_n05", [_allow("dynamodb:Query", internal_table["arn"])], [internal_table],
                              {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})},
        {"id": "N06", "name": "Write access to public bucket blocked by explicit Deny", "expected": "benign",
         "scenario": via_role("bench_n06", [_allow("s3:GetObject", "arn:aws:s3:::public-assets/*"),
                                            {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"}], [public_bucket])},
    ]


def _worst(labels: List[str]) -> Optional[str]:
    return max(labels, key=ORDER.index) if labels else None


def assess(entry: Dict[str, Any], models: Dict[str, Any], feature_columns: List[str]) -> Dict[str, Any]:
    raw = entry["scenario"]
    context = context_from_scenario(raw)
    paths = [p.to_dict() for p in discover_paths(build_attack_graph(normalize_scenario(raw)), context)]
    result = {k: entry[k] for k in ("id", "name", "expected")}
    result["group"] = entry.get("group", "Modelled scenario" if entry["expected"] == "attack" else "Negative control")
    result["paths_found"] = len(paths)
    if not paths:
        result.update(random_forest=None, hybrid=None, rules=None)
        return result
    rows = pd.DataFrame([build_feature_row(p, context) for p in paths])
    rf = [p["predicted_label"] for p in predict_frame(rows, {"random_forest": models["random_forest"]}, feature_columns)]
    result["random_forest"] = _worst(rf)
    result["hybrid"] = _worst(apply_escalation_floor(rf, rows))
    result["rules"] = _worst(predict_rule_based(rows))
    return result


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    attacks = [r for r in results if r["expected"] == "attack"]
    benign = [r for r in results if r["expected"] == "benign"]
    for method in ("random_forest", "hybrid", "rules"):
        detected = sum(r[method] in SEVERE for r in attacks)
        false_alarms = sum(r[method] in SEVERE for r in benign)
        summary[method] = {
            "attacks_detected": f"{detected}/{len(attacks)}",
            "detection_rate": round(detected / len(attacks), 4),
            "false_alarms": f"{false_alarms}/{len(benign)}",
        }
    summary["attack_paths_found"] = f"{sum(r['paths_found'] > 0 for r in attacks)}/{len(attacks)}"
    return summary


def write_report(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    lines = [
        "# External Benchmark: Known IAM Privilege-Escalation Techniques",
        "",
        "Detected = some attack path rated HIGH or CRITICAL. Cells show the worst label over the scenario's paths.",
        "",
        "| Method | Attacks detected | Detection rate | False alarms on benign controls |",
        "|---|---:|---:|---:|",
    ]
    for method in ("random_forest", "hybrid", "rules"):
        s = summary[method]
        lines.append(f"| {method} | {s['attacks_detected']} | {s['detection_rate']:.1%} | {s['false_alarms']} |")
    lines += [
        "",
        f"Attack scenarios with at least one attack path discovered: {summary['attack_paths_found']}.",
        "",
        "| ID | Technique | Paths | Random Forest | Hybrid | Static rules |",
        "|---|---|---:|---|---|---|",
    ]
    for r in results:
        cells = [r[m] or "no path" for m in ("random_forest", "hybrid", "rules")]
        lines.append(f"| {r['id']} | {r['name']} | {r['paths_found']} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(args: list = None) -> int:
    argparse.ArgumentParser(prog="python -m experiments.benchmark", description=__doc__.splitlines()[0]).parse_args(args)
    models = _load_available_models()
    feature_columns = joblib.load(MODELS_DIR / "feature_columns.pkl")
    results = [assess(entry, models, feature_columns) for entry in rhino_techniques() + modelled_scenarios() + negative_controls()]
    summary = summarize(results)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps({"summary": summary, "scenarios": results}, indent=2))
    report = write_report(results, summary)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(report)
    print(f"[SUCCESS] Benchmark results written to: {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
