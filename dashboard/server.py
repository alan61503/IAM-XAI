"""Phase 10: Interactive Dashboard HTTP Server & REST API.

Provides backend API endpoints for analyzing IAM configurations end-to-end,
executing graph path traversal, ML risk prediction, SHAP explanations, choke point detection,
and 1-click policy remediations.
"""

from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd

from choke_point.choke_finder import identify_scenario_choke_points
from dataset.generator import DEFAULT_MAX_HOPS, discover_paths
from dataset.row_builder import build_feature_row, context_from_scenario
from graph.graph_builder import build_attack_graph
from models.baselines import predict_rule_based
from models.predict import PRIMARY_MODEL, _load_available_models, predict_frame
from parser.normalizer import normalize_scenario
from path.path_serializer import serialize_paths_to_dict
from remediation.diff_generator import generate_policy_diff, generate_remediation_playbook
from remediation.policy_remediator import remediate_choke_point
from remediation.simulator import verify_remediation

try:
    from explainability.explain_prediction import explain_rows
except Exception:  # SHAP (or its numba dependency) unavailable in this environment
    explain_rows = None

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROJECT_DIR = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = PROJECT_DIR / "data" / "scenarios"
FEATURE_COLUMNS_PATH = PROJECT_DIR / "models" / "feature_columns.pkl"
SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_BODY_BYTES = 5 * 1024 * 1024


@lru_cache(maxsize=1)
def _load_model_bundle() -> Tuple[Dict[str, Any], Optional[List[str]]]:
    """Load trained models and their feature columns once per process."""
    models = _load_available_models()
    feature_cols = joblib.load(FEATURE_COLUMNS_PATH) if FEATURE_COLUMNS_PATH.exists() else None
    return models, feature_cols


def _predict_and_explain(rows: pd.DataFrame) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """ML predictions plus SHAP explanations; static-rule fallback when no models are trained."""
    if rows.empty:
        return [], []
    models, feature_cols = _load_model_bundle()
    if not (models and feature_cols):
        labels = predict_rule_based(rows)
        predictions = [
            {"path_id": pid, "predicted_label": label, "predicted_score": None, "confidence": None, "source": "rules"}
            for pid, label in zip(rows["path_id"], labels)
        ]
        return predictions, []

    predictions = [
        {"path_id": pid, **pred, "source": "ml"}
        for pid, pred in zip(rows["path_id"], predict_frame(rows, models, feature_cols))
    ]
    explanations: List[Dict[str, Any]] = []
    if explain_rows is not None and PRIMARY_MODEL in models:
        explanations = explain_rows(rows, feature_columns=feature_cols, model=models[PRIMARY_MODEL])
    return predictions, explanations


def analyze_scenario_end_to_end(raw_scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Run full IAM-XAI pipeline (Phases 1-9) on raw IAM scenario dictionary."""
    scenario_id = raw_scenario.get("scenario_id", "scenario_custom")

    # Phase 1 & 2: Parser & Graph Builder
    normalized = normalize_scenario(raw_scenario)
    graph = build_attack_graph(normalized)
    serialized_graph = graph.to_dict()

    # Phase 3: Attack Path Enumeration (same discovery as the training data, incl. PassRole targets)
    context = context_from_scenario(raw_scenario)
    paths = discover_paths(graph, context, max_hops=DEFAULT_MAX_HOPS)
    paths_data = serialize_paths_to_dict(paths, scenario_id=scenario_id, max_hops=DEFAULT_MAX_HOPS)

    # Phase 4-7: shared feature rows -> ML prediction -> SHAP explanation
    rows = pd.DataFrame([build_feature_row(path, context) for path in paths_data.get("paths", [])])
    predictions, explanations = _predict_and_explain(rows)

    # Phase 8: Choke Point Detection
    choke_points = identify_scenario_choke_points(paths_data.get("paths", []), explanations, predictions)

    # Phase 9: Remediation Engine
    top_choke = choke_points[0] if choke_points else None
    remediation = None
    if top_choke:
        remediated_scenario, summary = remediate_choke_point(raw_scenario, top_choke)
        diff = generate_policy_diff(raw_scenario, remediated_scenario)
        verification = verify_remediation(raw_scenario, remediated_scenario)
        playbook = generate_remediation_playbook(top_choke, summary, verification)
        remediation = {
            "summary": summary,
            "diff": diff,
            "verification": verification,
            "playbook": playbook,
            "remediated_scenario": remediated_scenario,
        }

    # Summary metrics
    labels = [p["predicted_label"] for p in predictions]
    overall_risk = "CRITICAL" if "CRITICAL" in labels else ("HIGH" if "HIGH" in labels else ("MEDIUM" if "MEDIUM" in labels else "LOW"))

    return {
        "scenario_id": scenario_id,
        "raw_scenario": raw_scenario,
        "overall_risk_label": overall_risk,
        "total_nodes": len(serialized_graph.get("nodes", [])),
        "total_edges": len(serialized_graph.get("edges", [])),
        "total_paths": len(paths_data.get("paths", [])),
        "graph": serialized_graph,
        "paths": paths_data.get("paths", []),
        "predictions": predictions,
        "explanations": explanations,
        "choke_points": choke_points,
        "remediation": remediation,
    }


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP handler for static assets and REST API endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress default stdout logging for clean test/terminal runs

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path: Path, mime_type: str) -> None:
        if not file_path.exists():
            self.send_error(404, "File Not Found")
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/":
            self._send_file(STATIC_DIR / "index.html", "text/html")
        elif path == "/style.css":
            self._send_file(STATIC_DIR / "style.css", "text/css")
        elif path == "/app.js":
            self._send_file(STATIC_DIR / "app.js", "application/javascript")
        elif path == "/api/scenarios":
            scenarios = []
            if SCENARIOS_DIR.exists():
                for sf in sorted(SCENARIOS_DIR.glob("*.json")):
                    try:
                        data = json.loads(sf.read_text(encoding="utf-8"))
                        scenarios.append({
                            "id": sf.stem,
                            "filename": sf.name,
                            "description": data.get("description", f"Scenario {sf.stem}"),
                        })
                    except Exception:
                        pass
            self._send_json({"scenarios": scenarios})
        elif path.startswith("/api/scenario/"):
            scen_id = path.replace("/api/scenario/", "")
            target_file = SCENARIOS_DIR / f"{scen_id}.json"
            if not SCENARIO_ID_RE.match(scen_id):
                self._send_json({"error": "Invalid scenario id"}, 400)
            elif target_file.exists():
                raw = json.loads(target_file.read_text(encoding="utf-8"))
                result = analyze_scenario_end_to_end(raw)
                self._send_json(result)
            else:
                self._send_json({"error": f"Scenario {scen_id} not found"}, 404)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len > MAX_BODY_BYTES:
            self._send_json({"error": "Request body too large"}, 413)
            return
        post_data = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            payload = json.loads(post_data.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Invalid JSON body"}, 400)
            return

        if self.path == "/api/analyze":
            try:
                result = analyze_scenario_end_to_end(payload)
                self._send_json(result)
            except Exception as e:
                traceback.print_exc(file=sys.stderr)
                self._send_json({"error": str(e)}, 500)
        elif self.path == "/api/remediate":
            try:
                scenario = payload.get("scenario")
                choke_point = payload.get("choke_point")
                if not scenario or not choke_point:
                    self._send_json({"error": "Missing scenario or choke_point payload"}, 400)
                    return
                remediated, summary = remediate_choke_point(scenario, choke_point)
                result = analyze_scenario_end_to_end(remediated)
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_error(404)


def run_dashboard_server(port: int = 8000, host: str = "127.0.0.1") -> None:
    """Run interactive dashboard HTTP server (localhost only unless ``host`` says otherwise)."""
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    print(f"[IAM-XAI Dashboard] Server running at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()
