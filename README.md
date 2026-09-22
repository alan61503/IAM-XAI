# IAM-XAI: Explainable Attack Path Risk Assessment for Cloud Identity Configurations

IAM-XAI models AWS Identity and Access Management (IAM) configurations as attack graphs, finds privilege-escalation and lateral-movement paths, predicts each path's risk with machine learning, explains every prediction with SHAP, identifies the choke-point permissions whose removal cuts the most risk, and proposes verified remediations -- all without touching a real AWS account.

**Headline results** (full details in [`evaluation/RESULTS.md`](evaluation/RESULTS.md)):

| Question | Result |
|---|---|
| Risk classification on environments never seen in training | Random Forest macro F1 **0.881** (95% CI 0.870–0.891); static rules 0.390; best achievable ≈ 0.891 |
| Attack patterns never seen in training | Hybrid model (ML + escalation floor) has **0% severe misses** on unseen admin / policy-rewrite / PassRole escalation (pure ML: up to 97%) |
| Are SHAP explanations right? | Top SHAP feature names a true risk cause for **95%** of paths; SHAP beats a global-importance ranking on cause recall and deletion fidelity |
| Choke-point remediation | 3 greedy cuts remove **52.3%** of real risk (optimal: 52.7%; most-shared-edge baseline: 43.9%) |
| Known published attacks | **18/26** documented IAM escalation techniques detected, **0/6** false alarms |

---

## Contents

1. [Quick Start](#quick-start)
2. [Pipeline and Repository Layout](#pipeline-and-repository-layout)
3. [Phase 1: IAM Configuration Parsing](#phase-1-iam-configuration-parsing-and-normalization)
4. [Phase 2: Attack Graph Construction](#phase-2-attack-graph-construction)
5. [Phase 3: Attack Path Detection](#phase-3-attack-path-detection)
6. [Phase 4: Path Feature Extraction](#phase-4-path-feature-extraction)
7. [Phase 5: Synthetic Dataset Generation](#phase-5-synthetic-dataset-generation)
8. [Phase 6: ML Risk Assessment](#phase-6-machine-learning-risk-assessment)
9. [Phase 7: Explainable AI (SHAP)](#phase-7-explainable-ai-using-shap)
10. [Phase 8: Choke Point Detection](#phase-8-choke-point-detection)
11. [Phase 9: Remediation Engine](#phase-9-remediation-engine)
12. [Phase 10: Interactive Dashboard](#phase-10-interactive-dashboard)
13. [Research Evaluation](#research-evaluation)
14. [Command Reference](#command-reference)
15. [Scope and Known Limitations](#scope-and-known-limitations)

---

## Quick Start

Requires Python 3.11+. Use a virtual environment: `requirements.txt` pins exact versions because `numba` (needed by `shap`) does not support NumPy ≥ 2.3, and the saved `models/*.pkl` must be loaded with the scikit-learn version that trained them.

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt        # Windows; use .venv/bin/pip on Linux/macOS

# Use the venv interpreter for every command below (.venv/Scripts/python or .venv/bin/python)
python -m dataset.main --count 3000 --workers 4 --output data/processed/iam_attack_dataset.csv
python -m models.train                                # train, tune, evaluate (~1-2 min)
python -m dashboard.main                              # http://127.0.0.1:8000
python -m pytest -q                                   # 222 tests
```

The trained models and dataset are committed, so the dashboard and prediction CLIs work straight after installing.

---

## Pipeline and Repository Layout

```
IAM configuration (JSON)
  → Phase 1  parser/          normalize entities, permissions, trust relationships
  → Phase 2  graph/           directed attack graph (CAN_ASSUME / CAN_ACCESS / CAN_MODIFY / CAN_PASS_ROLE)
  → Phase 3  path/            bounded, cycle-safe attack path enumeration (explicit Deny honored)
  → Phase 4  features/        per-path feature vectors
  → Phase 5  dataset/         synthetic environments + ground-truth risk oracle → labeled CSV
  → Phase 6  models/          Logistic Regression / Random Forest / XGBoost (+ hybrid escalation floor)
  → Phase 7  explainability/  SHAP TreeExplainer: local + global explanations
  → Phase 8  choke_point/     edges whose removal eliminates the most predicted risk
  → Phase 9  remediation/     least-privilege policy patch + re-verification + playbook
  → Phase 10 dashboard/       web UI over the whole pipeline
```

| Folder | Contents |
|---|---|
| `parser/`, `graph/`, `path/`, `features/` | Phases 1–4 (standard library only) |
| `dataset/` | Environment generator, shared feature-row builder, risk oracle, dataset CLI |
| `models/` | Preprocessing, training/tuning, evaluation & statistics, prediction, baselines, saved models |
| `explainability/` | SHAP explainer, explanations, plots, faithfulness evaluation |
| `choke_point/`, `remediation/`, `dashboard/` | Phases 8–10 (+ choke-point evaluation) |
| `experiments/` | Sensitivity analysis, external benchmark, paper figures, results summary |
| `data/scenarios/` | 9 hand-written example IAM scenarios |
| `data/processed/` | Generated dataset CSV + distribution report |
| `evaluation/` | All metrics, reports, SHAP plots and paper figures |
| `docs/` | Project report |
| `tests/` | 222 unit and integration tests |

---

## Phase 1: IAM Configuration Parsing and Normalization

Phase 1 ingests synthetic AWS IAM configuration JSON (users, groups, roles with trust policies and permissions, resources) and normalizes it into a deterministic representation of entities, permissions and trust relationships. Both AWS-style (`Effect`, `Action`, `Resource`, `Statement`) and lower-case field names are accepted; malformed input raises `IAMValidationError` with a precise location.

```bash
python -m parser.main data/scenarios/scenario_001.json --output output/scenario_001_normalized.json
```

---

## Phase 2: Attack Graph Construction

Phase 2 converts the normalized representation into a **directed attack graph** of possible privilege relationships between IAM identities and cloud resources.

### 1. Graph Model

The graph is a directed graph $G = (V, E)$:
- **Nodes ($V$)**: IAM identities and cloud resources, with prefix-based ids: `user:<name>`, `role:<name>`, `resource:<name>`, `group:<name>`, `service:<name>` (e.g. `service:ec2.amazonaws.com`), `principal:*`. Attributes: `id`, `type`, `name`, optional `arn`, optional `resource_type`, `metadata`.
- **Edges ($E$)**: privilege relationships from trust policies or permission statements. Attributes: `source`, `target`, `edge_type`, `effect`, `actions`, `resources`, `conditions`, `metadata`. The graph keeps an adjacency index, so outgoing-edge lookups are O(1).

### 2. Edge Types

| Edge Type | Description | Representative Actions |
| :--- | :--- | :--- |
| `CAN_ASSUME` | Identity can assume target IAM role | `sts:AssumeRole`, `sts:AssumeRoleWithSAML` |
| `CAN_ACCESS` | Identity has read / query permissions | `s3:GetObject`, `s3:ListBucket`, `dynamodb:Query`, `secretsmanager:GetSecretValue` |
| `CAN_MODIFY` | Identity has write / mutate / delete permissions | `s3:PutObject`, `s3:DeleteObject`, `dynamodb:PutItem`, `iam:CreatePolicyVersion` |
| `CAN_PASS_ROLE` | Identity can pass a role to a service | `iam:PassRole` |

### 3. Action Classification (`graph/action_mapper.py`)

- **Exact mappings** (e.g. `s3:GetObject` → `CAN_ACCESS`) and **prefix mappings** (`*:get*` → `CAN_ACCESS`, `*:put*` → `CAN_MODIFY`).
- `iam:PassRole` maps strictly to `CAN_PASS_ROLE` and never implies `CAN_ASSUME`.
- `s3:*` maps to `CAN_ACCESS` + `CAN_MODIFY` with `action_scope: "service_wildcard"`, `broad_permission: true`; the full wildcard `*` maps to data access and modification (`action_scope: "wildcard"`) but never creates `CAN_ASSUME` or `CAN_PASS_ROLE` -- those need explicit intent and trust.
- The original action strings are preserved on every edge for feature extraction and SHAP.

### 4. Resource Matching & Node Provenance (`graph/resource_matcher.py`)

- Declared entities carry `"metadata": {"synthetic": false}`; undeclared resources referenced by permissions become synthetic nodes (`"source": "permission_resource"`).
- S3 object ARNs match their bucket (`arn:aws:s3:::example-bucket/*` → `resource:ExampleBucket`); role ARNs match role nodes; `CAN_ASSUME`/`CAN_PASS_ROLE` resolve only to roles; `arn:aws:s3:::*` matches all S3 resources; `*` matches all resources.
- Trust-policy principals are tagged `principal_type` = `internal`, `service`, `external` (undeclared principal) or `wildcard` (`Principal: "*"`).

### 5. Allow vs. Deny

- `Deny` statements are preserved as edges with `effect: "Deny"` and are never traversed as attacker capabilities.
- Phase 3 applies **explicit deny overrides allow** (`path/traversal_policy.py`): an `Allow` edge is blocked when unconditional `Deny` edges between the same two nodes cover all of its resource patterns and remove every action it grants. `Deny s3:*` blocks `Allow s3:GetObject`; `Deny s3:DeleteObject` leaves the rest of `Allow s3:*` usable; a deny on `bucket/secret/*` does not block an allow on `bucket/*`.
- Conditional denies are assumed not to apply (attacker-favorable), since request context is unknown.

### 6. Conditions

Conditions (`aws:MultiFactorAuthPresent`, `aws:SourceIp`, `sts:ExternalId`, ...) are kept verbatim on edges. They are not evaluated as true/false; they feed path features (Phase 4) and the risk oracle's mitigation factors (Phase 5).

### 7. Serialization Format

Graphs serialize deterministically (nodes sorted by `id`, edges by `(source, target, edge_type, effect, actions)`):

```json
{
  "scenario_id": "scenario_001",
  "nodes": [
    {"id": "resource:ExampleBucket", "type": "resource", "name": "ExampleBucket",
     "arn": "arn:aws:s3:::example-bucket", "resource_type": "s3"},
    {"id": "role:RoleA", "type": "role", "name": "RoleA"},
    {"id": "user:UserA", "type": "user", "name": "UserA"}
  ],
  "edges": [
    {"source": "role:RoleA", "target": "resource:ExampleBucket", "edge_type": "CAN_ACCESS",
     "effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::example-bucket/*"],
     "conditions": {}, "metadata": {"origin": "permission"}},
    {"source": "user:UserA", "target": "role:RoleA", "edge_type": "CAN_ASSUME",
     "effect": "Allow", "actions": ["sts:AssumeRole"], "resources": [],
     "conditions": {}, "metadata": {"origin": "trust_policy", "principal_type": "internal"}}
  ]
}
```

```bash
python -m graph.main output/scenario_001_normalized.json --output output/scenario_001_graph.json
```

---

## Phase 3: Attack Path Detection

Phase 3 enumerates multi-hop privilege-escalation and lateral-movement paths from attacker entry points (users, including undeclared external principals) to cloud resources.

- **Attack path**: `source`, `target`, ordered `nodes` and `edges` (with full IAM metadata), `hop_count`, `conditional` (any traversed edge has conditions), `edge_types`.
- **Traversal semantics** (`path/traversal_policy.py`): `CAN_ASSUME` pivots into the role and continues from its permissions; `CAN_PASS_ROLE` reaches the role but does **not** grant its permissions; `CAN_ACCESS`/`CAN_MODIFY` reach resources; only `Allow` edges not overridden by explicit `Deny` are traversed.
- **Enumeration** (`path/path_finder.py`): simple paths only (no repeated node), bounded by `--max-hops` (default 5 for the CLI, 6 for dataset generation), deterministic ordering.
- **Filtering** (`path/path_filter.py`): `--min-hops`, `--max-hops`, `--source`, `--target`, `--edge-types` without re-running traversal.

```json
{
  "scenario_id": "scenario_009",
  "max_hops": 5,
  "total_paths": 2,
  "paths": [
    {
      "path_id": "scenario_009_path_001",
      "source": "user:InitialUser",
      "target": "resource:ProductionDataBucket",
      "nodes": ["user:InitialUser", "role:IntermediateRoleA", "role:TargetRoleB", "resource:ProductionDataBucket"],
      "edges": [ ... ],
      "hop_count": 3,
      "conditional": false,
      "edge_types": ["CAN_ASSUME", "CAN_ASSUME", "CAN_ACCESS"]
    }
  ]
}
```

```bash
python -m path.main output/scenario_009_graph.json --output output/scenario_009_paths.json
python -m path.main output/scenario_009_graph.json --source user:InitialUser --target resource:ProductionDataBucket --max-hops 5 --output output/scenario_009_paths.json
python -m path.main output/scenario_009_graph.json --min-hops 2 --output output/scenario_009_multihop_paths.json
```

---

## Phase 4: Path Feature Extraction

`extract_features(path)` (`features/feature_extractor.py`) turns one attack path into a deterministic record matching `features/feature_schema.py`'s ~45 ordered features: path structure (`hop_count`, `role_count`, ...), edge-type counts (`assume_count`, `has_passrole`, ...), permission breadth (`wildcard_action_count`, `has_wildcard_resource`, ...), trust/principal features (`external_principal_count`, `has_wildcard_principal`, ...), condition features, effect counts, target metadata and composition ratios.

```bash
python -m features.main output/scenario_009_paths.json --output output/scenario_009_features.json
python -m features.main output/scenario_009_paths.json --format csv --output output/scenario_009_features.csv
```

---

## Phase 5: Synthetic Dataset Generation

Phase 5 produces a large labeled dataset of attack paths, since no real AWS accounts are used. It runs Phases 1→4 in-process over randomly generated IAM environments.

### 1. Environments and Attack Patterns (`dataset/scenario_library.py`)

`build_environment` creates one environment sized per CLAUDE.md 5.2 (3–20 users, 2–15 roles, 5–30 resources across S3, DynamoDB, Lambda, EC2, Secrets Manager and KMS) with ordinary least-privilege access: role trust from users and other roles, read/write permissions, occasional MFA or source-IP conditions, and explicit Deny guardrails on ~15% of roles. It then injects 0–3 attack patterns: `wildcard_action`, `wildcard_resource`, `pass_role` (to a privileged *or* an ordinary service role), `assume_chain` (2–4 roles), `external_trust`, `cross_account`, `wildcard_trust` (`Principal: "*"`), `policy_modification`, `admin_wildcard`. Injected trust can carry mitigating conditions (MFA, SourceIp, ExternalId).

Every resource has a true data classification tier (public / internal / confidential / restricted). As in real accounts, only ~85% of resources carry a `DataClassification` tag and ~5% of tags are one tier off. The model sees only the tag; the true tier is ground truth.

### 2. Orchestration (`dataset/generator.py`)

Each environment gets its own RNG seeded from `(seed, index)`, so output is reproducible and identical for any `--workers` count. Paths are discovered (max 6 hops, plus explicit PassRole targets), turned into feature rows and labeled. Each environment contributes at most `--max-paths-per-scenario` paths (default 30), sampled class-balanced, so one densely connected environment can't dominate.

### 3. Shared Feature Rows (`dataset/row_builder.py`)

`build_feature_row(path, context)` is the single place a path becomes model features, used by both the generator and the dashboard -- training and serving can't compute features differently (a test checks they are identical). `context_from_scenario(raw)` extracts only what an analyzer can see: resource types, classification tags, PassRole targets, and which roles hold administrator-equivalent (`*` / `iam:*`) permissions.

### 4. Ground-Truth Risk Oracle (`dataset/label_generator.py`)

Labels are **not** a rule over the model's own feature columns (that would make learning circular). `assess(path, row, meta)` computes

`risk_score = impact × (0.35 + 0.65 × likelihood)`

- **impact**: true classification tier of the target (+ write access), or administrator / policy-rewrite power, or whether a passed role is actually privileged;
- **likelihood**: entry exposure (public 1.0, external/cross-account 0.9, internal 0.6) × 0.9 per extra hop × a factor per mitigating condition (MFA 0.45, SourceIp 0.6, ExternalId 0.65).

Cut points 0.20 / 0.36 / 0.55 give LOW / MEDIUM / HIGH / CRITICAL. `risk_cause` names the drivers (e.g. `restricted_data + external_trust`, `confidential_data + mfa_mitigated`). All weights live in `OracleConfig` so the sensitivity analysis can perturb them; `--label-noise` optionally shifts a fraction of labels to an adjacent class. The original fixed rules (CLAUDE.md 5.4) are kept as a baseline in `models/baselines.py`.

### 5. Dataset Schema (`dataset/schema.py`)

- Identifiers: `scenario_id, path_id, source_identity, target_resource`
- Numeric features: `path_length, role_count, user_count, resource_count, action_count, wildcard_action_count, wildcard_resource_count, broad_permission_edge_count, conditional_edge_count, condition_key_count, distinct_service_count, classification_tag`
- Binary features: `assume_role, pass_role, wildcard_action, wildcard_resource, policy_modification, external_trust, cross_account, wildcard_principal, sensitive_target, admin_permission, write_access, has_conditions, target_privileged`
- Categorical features: `target_type, target_service`
- Ground truth (never model inputs): `risk_label, risk_score, attack_type, risk_cause, scenario_patterns, target_classification`

```bash
python -m dataset.main --count 3000 --seed 42 --workers 4 --output data/processed/iam_attack_dataset.csv
```
Also writes `data/processed/iam_attack_dataset_report.json` (label, attack-type, target and pattern distributions). The committed dataset has 76,479 paths from 3,000 environments; generation takes about 5 seconds with 4 workers.

---

## Phase 6: Machine Learning Risk Assessment

Phase 6 predicts `risk_label` for attack paths in environments never seen during training.

### 1. Preprocessing (`models/preprocess.py`)

Builds the feature matrix from the `dataset/schema.py` groups (one-hot `target_type`/`target_service`) and splits 70/15/15 train/val/test **grouped by `scenario_id`**, `random_state = 42`: all paths of one environment land in the same split.

### 2. Training and Evaluation (`models/train.py`, `models/evaluate.py`)

1. A small hyperparameter grid per model (Logistic Regression with scaling, Random Forest, XGBoost), selected on validation macro-F1.
2. The best configuration is refit on train+val and evaluated once on test: accuracy, balanced accuracy, macro/weighted precision/recall/F1, one-vs-rest ROC-AUC, confusion matrix, classification report, severe-miss rate (truly HIGH/CRITICAL paths rated LOW/MEDIUM), Random Forest feature importances.
3. Grouped bootstrap 95% confidence intervals (resampling whole test environments) and McNemar tests vs. Random Forest.
4. Grouped 5-fold cross-validation (mean ± std).
5. The static CLAUDE.md 5.4 rules on the same test set, as a baseline.
6. The **hybrid** model: Random Forest plus an escalation floor (`models/baselines.apply_escalation_floor`) -- admin-equivalent or policy-rewrite permission ≥ HIGH, PassRole of a privileged role ≥ HIGH, other PassRole ≥ MEDIUM.
7. Leave-one-pattern-out: Random Forest (and hybrid) trained on environments *without* a given attack pattern, tested on held-out paths exhibiting it.
8. Dataset diagnostics: distinct feature vectors, label-ambiguity ceiling (the best accuracy any model could reach), train/test feature-vector overlap.

Outputs `evaluation/model_metrics.json` and a readable `evaluation/model_report.md`. Models are saved (compressed) to `models/<name>.pkl` with `models/feature_columns.pkl`; XGBoost is wrapped in `models/estimators.LabelEncodedClassifier` so it takes string labels.

### 3. Results

| Model | Accuracy | Macro F1 [95% CI] | Severe-miss rate |
|---|---:|---|---:|
| Logistic Regression | 0.753 | 0.765 [0.753, 0.776] | 12.9% |
| Random Forest | 0.879 | 0.881 [0.870, 0.891] | 9.8% |
| XGBoost | 0.882 | 0.884 [0.874, 0.894] | 10.4% |
| Hybrid (RF + escalation floor) | 0.878 | 0.880 [0.869, 0.890] | 9.8% |
| Static rules (baseline) | 0.421 | 0.390 [0.371, 0.409] | 13.5% |

Label-ambiguity ceiling: 0.891. On attack patterns absent from training, pure Random Forest rates 96.8% of severe PassRole paths and 57.9% of severe admin paths LOW/MEDIUM; the hybrid brings both to 0.0%.

```bash
python -m models.train --input data/processed/iam_attack_dataset.csv
python -m models.predict --path-id synthetic_00023_path_001
```

```json
{
  "path_id": "synthetic_00023_path_001",
  "predicted_label": "CRITICAL",
  "predicted_score": 1.0,
  "confidence": 0.9719,
  "expected_risk": 0.85
}
```
`predicted_score` is the Random Forest probability of the predicted label, `confidence` the agreement across all trained models, and `expected_risk` the probability-weighted class severity (used by Phase 8).

---

## Phase 7: Explainable AI Using SHAP

- **Explainer** (`explainability/shap_explainer.py`): `shap.TreeExplainer` over the saved Random Forest (the designated explainability model); no background dataset needed.
- **Local explanations** (`explainability/explain_prediction.py`): `explain_path(path_id)` returns the top 6 SHAP contributors for the predicted class. `explain_rows` computes SHAP once per *distinct* feature vector and maps it back to every path sharing it (≈77k paths → ≈2k vectors: about 5 minutes instead of about 3 hours).
- **Plots** (`explainability/visualize.py`): global summary and feature-importance bar plots, plus waterfall / force / decision plots for single paths, in `evaluation/shap/`.
- **Faithfulness** (`explainability/faithfulness.py`): checks explanations against ground truth and against the model (see [Research Evaluation](#research-evaluation)).

Example -- restricted data written to through a cross-account trust relationship:
```json
{
  "path_id": "synthetic_00023_path_001",
  "prediction": "CRITICAL",
  "top_factors": [
    {"feature": "classification_tag", "impact": 0.338},
    {"feature": "sensitive_target", "impact": 0.1962},
    {"feature": "external_trust", "impact": 0.0732},
    {"feature": "wildcard_action_count", "impact": 0.034}
  ]
}
```

```bash
python -m explainability.export_explanation --path-id synthetic_00023_path_001
python -m explainability.export_explanation --all --output evaluation/shap/explanations.json
```

---

## Phase 8: Choke Point Detection

A choke point is a single permission edge that many risky attack paths depend on; removing it breaks all of them.

- **Per path** (`identify_path_choke_point`): maps the path's top SHAP factors back to the edges that carry them (e.g. `external_trust` → the `CAN_ASSUME` edge from an external principal; `policy_modification` → the edge holding a policy-rewrite action) and picks the highest-scoring edge.
- **Per scenario** (`identify_scenario_choke_points`): ranks every edge by the predicted risk (`expected_risk`) of the paths it blocks, with a bonus for paths sharing it and for SHAP evidence.
- **Budgeted cuts** (`select_choke_point_set(paths, predictions, k)`): greedy maximum coverage -- each pick is the edge on the most *remaining* predicted risk, so `k` cuts don't overlap on the same paths.

On 200 unseen environments, 3 greedy cuts remove 52.3% of ground-truth risk (optimal 52.7%, most-shared-edge baseline 43.9%, random 20.0%).

```bash
python -m choke_point.main output/scenario_009_paths.json --output output/scenario_009_choke.json
# optional: --explanations <SHAP JSON> --predictions <predictions JSON>
```

---

## Phase 9: Remediation Engine

- **Patch** (`remediation/policy_remediator.py`): turns the top choke point into a least-privilege change to the raw scenario -- `REVOKE_TRUST_POLICY_STATEMENT` or `ADD_MFA_CONDITION` for `CAN_ASSUME` edges; `RESTRICT_WILDCARD_PERMISSIONS` or `REMOVE_EXCESSIVE_PERMISSION_STATEMENT` for permission edges.
- **Diff** (`remediation/diff_generator.py`): before/after policy diff per entity, plus a Markdown remediation playbook.
- **Verification** (`remediation/simulator.py`): rebuilds the graph for the original and patched configurations and reports `FULLY_ELIMINATED`, `PARTIALLY_REDUCED` or `UNCHANGED`.

```bash
python -m remediation.main data/scenarios/scenario_009.json output/scenario_009_choke.json \
    --output output/scenario_009_remediation.json --playbook-output output/scenario_009_playbook.md
```

For `scenario_009` this revokes the trust statement letting `InitialUser` assume `IntermediateRoleA` and verifies both attack paths are eliminated (see `output/scenario_009_playbook.md`).

---

## Phase 10: Interactive Dashboard

A dependency-free web UI (`dashboard/server.py`, `dashboard/static/`) that runs the whole pipeline on a bundled or pasted scenario: attack graph, paths with ML risk labels, real SHAP explanations per path, ranked choke points, and one-click remediation with re-analysis.

```bash
python -m dashboard.main            # http://127.0.0.1:8000 (use --host 0.0.0.0 to expose on a network)
```

| Endpoint | Purpose |
|---|---|
| `GET /api/scenarios` | List `data/scenarios/*.json` |
| `GET /api/scenario/<id>` | Analyze a bundled scenario (ids restricted to `[A-Za-z0-9_-]`) |
| `POST /api/analyze` | Analyze a scenario JSON body (≤ 5 MB) |
| `POST /api/remediate` | Apply a choke-point patch, then re-analyze |

Models are loaded once per process; predictions are batched. Without trained models the dashboard falls back to the static rules; without SHAP it omits explanations. The bundled scenarios carry no `DataClassification` tags, so their data is treated as unclassified -- add `"tags": {"DataClassification": "restricted"}` to a resource to see it scored as sensitive.

---

## Research Evaluation

Every experiment writes JSON (and a readable Markdown report) under `evaluation/`. `experiments.summary` combines them into [`evaluation/RESULTS.md`](evaluation/RESULTS.md); `experiments.figures` renders the paper figures to `evaluation/figures/`.

| Command | Question | Output |
|---|---|---|
| `python -m models.train` | RQ1/RQ2: accuracy on unseen environments, CIs, significance, unseen-pattern generalization | `model_metrics.json`, `model_report.md` |
| `python -m explainability.faithfulness` | RQ3: do SHAP explanations name the true cause, and are they faithful to the model? | `explanation_faithfulness.json` |
| `python -m choke_point.evaluate` | RQ4: how much ground-truth risk do IAM-XAI's choke points remove vs. baselines? | `choke_point_evaluation.json` |
| `python -m experiments.sensitivity` | RQ5: do conclusions survive label noise and changed oracle weights / cut points? | `sensitivity_analysis.json`, `.md` |
| `python -m experiments.benchmark` | RQ6: are 21 published IAM escalation methods, 5 CloudGoat-style scenarios and 6 benign controls classified correctly? | `benchmark_results.json`, `.md` |
| `python -m experiments.figures` | Paper figures 1–6 | `figures/*.png` |
| `python -m experiments.summary` | One consolidated results document | `RESULTS.md` |

Run them in this order after `dataset.main`; the whole sequence takes roughly 25 minutes on a laptop.

---

## Command Reference

| Phase | Command |
|---|---|
| 1 | `python -m parser.main <scenario.json> --output <normalized.json>` |
| 2 | `python -m graph.main <normalized-or-raw.json> --output <graph.json>` |
| 3 | `python -m path.main <graph.json> [--source ID] [--target ID] [--min-hops N] [--max-hops N] --output <paths.json>` |
| 4 | `python -m features.main <paths.json> [--format csv] --output <features.json>` |
| 5 | `python -m dataset.main --count N [--seed 42] [--workers N] [--max-paths-per-scenario 30] [--label-noise 0] --output <dataset.csv>` |
| 6 | `python -m models.train [--input CSV] [--skip-generalization]`; `python -m models.predict --path-id ID` |
| 7 | `python -m explainability.export_explanation (--path-id ID \| --all) [--output FILE]` |
| 8 | `python -m choke_point.main <paths.json> [--explanations F] [--predictions F] --output <choke.json>` |
| 9 | `python -m remediation.main <scenario.json> <choke.json> --output <remediation.json> [--playbook-output <playbook.md>]` |
| 10 | `python -m dashboard.main [--port 8000] [--host 127.0.0.1]` |
| Tests | `python -m pytest -q` |

---

## Scope and Known Limitations

- **Posture assessment, not detection.** IAM-XAI scores latent risk in a given configuration; it does not analyze live logs/CloudTrail or connect to AWS.
- **Synthetic ground truth.** Training labels come from a risk oracle designed by the authors. The sensitivity analysis (RQ5) and the external benchmark (RQ6) test how much the conclusions depend on it.
- **Escalation mechanisms not modelled** (the 8 benchmark misses): credential takeover of another user (`iam:CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`), group-membership changes (`iam:AddUserToGroup`), rewriting the policy of a role the attacker can already assume, and code injection into privileged services (`lambda:UpdateFunctionCode`, `glue:UpdateDevEndpoint`).
- **Conditions** are treated as mitigations, not evaluated; conditional denies are assumed not to apply.
- **Remediation** of a `CAN_ASSUME` choke point currently revokes every AssumeRole statement of the target role, not only the one for the specific principal, and choke-point evaluation assumes any edge can be cut without business impact.
- **Path enumeration is exponential** in dense graphs (≈115k paths at 5 hops and ≈364k at 6 hops on a dense 65-node test graph); the dataset caps paths per environment.
