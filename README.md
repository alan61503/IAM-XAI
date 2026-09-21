# Explainable Attack Path Risk Assessment for Cloud Identity Configurations

This project implements an end-to-end framework for analyzing, modeling, and explaining security risk across cloud identity configurations (IAM).

---

## Architecture Overview

- **Phase 1: IAM Configuration Parsing and Normalization** (Completed)
- **Phase 2: Attack Graph Construction** (Completed)
- **Phase 3: Attack Path Traversal & Detection** (Completed)
- **Phase 4: Path Feature Extraction** (Completed)
- **Phase 5: Synthetic Dataset Generation** (Completed)
- **Phase 6: Machine Learning Risk Assessment** (Completed)
- **Phase 7: Explainable AI (XAI / SHAP)** (Completed)
- **Phase 8: Choke Point Detection** (Completed)
- **Phase 9: Remediation Engine** (Completed)
- **Phase 10: Interactive Dashboard** (Completed)

---

## Phase 1: IAM Configuration Parsing and Normalization

Phase 1 provides a modular Python parser that ingests synthetic AWS IAM configuration JSON files and normalizes them into a standardized, deterministic representation of cloud entities, permissions, and trust relationships.

### Phase 1 CLI
```bash
python -m parser.main data/scenarios/scenario_001.json --output output/scenario_001_normalized.json
```

---

## Phase 2: Attack Graph Construction

Phase 2 takes the standardized, normalized IAM representation produced by Phase 1 and converts it into a **directed attack graph** representing possible privilege relationships between IAM identities and cloud resources.

### 1. Graph Model

The graph is modeled as a directed graph $G = (V, E)$:
- **Nodes ($V$)**: IAM identities and cloud resources.
  - Prefix-based unique identifiers:
    - `user:<name>` (e.g. `user:UserA`)
    - `role:<name>` (e.g. `role:RoleA`)
    - `resource:<name>` (e.g. `resource:ExampleBucket`)
    - `group:<name>` (e.g. `group:AdminGroup`)
    - `service:<name>` (e.g. `service:ec2.amazonaws.com`)
    - `principal:<name>` (e.g. `principal:*`)
  - Node attributes: `id`, `type`, `name`, optional `arn`, optional `resource_type`, and `metadata`.
- **Edges ($E$)**: Privilege relationships resulting from trust policies or permission statements.
  - Attributes: `source`, `target`, `edge_type`, `effect`, `actions`, `resources`, `conditions`, `metadata`.

### 2. Edge Types

| Edge Type | Description | Representative Actions |
| :--- | :--- | :--- |
| `CAN_ASSUME` | Identity can assume target IAM role | `sts:AssumeRole`, `sts:AssumeRoleWithSAML` |
| `CAN_ACCESS` | Identity has read / query permissions | `s3:GetObject`, `s3:ListBucket`, `dynamodb:Query`, `secretsmanager:GetSecretValue`, `sqs:ReceiveMessage` |
| `CAN_MODIFY` | Identity has write / mutate / delete permissions | `s3:PutObject`, `s3:DeleteObject`, `dynamodb:PutItem`, `sqs:SendMessage` |
| `CAN_PASS_ROLE` | Identity can pass role to a service | `iam:PassRole` |

### 3. Action Classification Layer (`graph/action_mapper.py`)

Action mapping is extensible and centralized:
- **Exact mappings**: Direct 1-to-1 or 1-to-many lookups (e.g., `s3:GetObject` $\to$ `CAN_ACCESS`).
- **PassRole distinction**: `iam:PassRole` strictly maps to `CAN_PASS_ROLE` and does **not** create or imply `CAN_ASSUME`.
- **Prefix mappings**: Wildcard action patterns (e.g., `*:get*` $\to$ `CAN_ACCESS`, `*:put*` $\to$ `CAN_MODIFY`).
- **Conservative wildcard preservation**:
  - `s3:*` maps to `CAN_ACCESS` and `CAN_MODIFY` with `action_scope: "service_wildcard"` and `broad_permission: true`.
  - Full wildcard `*` maps conservatively to data access and modification (`CAN_ACCESS`, `CAN_MODIFY`) with `action_scope: "wildcard"` and `broad_permission: true`.
  - Full wildcard `*` does **not** create `CAN_ASSUME` or `CAN_PASS_ROLE` edges. Role assumption and role passing require specific operational intents (`sts:AssumeRole`, `iam:PassRole`) and trust relationships.
  - The original wildcard action string (`["*"]`, `["s3:*"]`) is strictly preserved on the generated edge for downstream risk scoring and SHAP analysis.

### 4. Resource Matching Engine & Node Provenance (`graph/resource_matcher.py`)

Matches permission resource patterns to known graph nodes without requiring live AWS infrastructure:
- **Node Provenance**:
  - Declared entities from input are marked with `"metadata": {"synthetic": false}`.
  - Undeclared resources referenced in permissions are synthesized as nodes marked with `"metadata": {"synthetic": true, "source": "permission_resource"}`.
- **S3 Object-to-Bucket matching**: `arn:aws:s3:::example-bucket/*` correctly matches node `resource:ExampleBucket` (`arn:aws:s3:::example-bucket`).
- **Role ARN matching**: `arn:aws:iam::...:role/TargetRoleB` matches `role:TargetRoleB`.
- **Target Role Constraint**: Actions with `CAN_ASSUME` or `CAN_PASS_ROLE` strictly resolve to `role` nodes.
- **Service wildcards**: `arn:aws:s3:::*` matches all S3 resources.
- **Global wildcard**: `*` matches all resource nodes.

### 5. Handling of Allow vs. Deny

- `Deny` relationships are **never discarded**; they are preserved as explicit edges in the graph with `effect: "Deny"`.
- This ensures future phases can evaluate whether a path is blocked or overridden by explicit denies, while preventing `Deny` edges from being mistaken for attacker capabilities.

### 6. Handling of Conditions

- Conditions (e.g., `aws:MultiFactorAuthPresent`, `aws:SourceIp`) are retained verbatim in the edge's `conditions` dictionary.
- Conditions are not evaluated during Phase 2; they are preserved as first-class edge metadata for path feature extraction (Phase 4) and explanation (Phase 7).

### 7. Serialization Format

Graphs serialize deterministically to JSON (nodes sorted by `id`, edges sorted by `(source, target, edge_type, effect, actions)`):

```json
{
  "scenario_id": "scenario_001",
  "nodes": [
    {
      "id": "resource:ExampleBucket",
      "type": "resource",
      "name": "ExampleBucket",
      "arn": "arn:aws:s3:::example-bucket",
      "resource_type": "s3"
    },
    {
      "id": "role:RoleA",
      "type": "role",
      "name": "RoleA"
    },
    {
      "id": "user:UserA",
      "type": "user",
      "name": "UserA"
    }
  ],
  "edges": [
    {
      "source": "role:RoleA",
      "target": "resource:ExampleBucket",
      "edge_type": "CAN_ACCESS",
      "effect": "Allow",
      "actions": [
        "s3:GetObject"
      ],
      "resources": [
        "arn:aws:s3:::example-bucket/*"
      ],
      "conditions": {},
      "metadata": {
        "origin": "permission"
      }
    },
    {
      "source": "user:UserA",
      "target": "role:RoleA",
      "edge_type": "CAN_ASSUME",
      "effect": "Allow",
      "actions": [
        "sts:AssumeRole"
      ],
      "resources": [],
      "conditions": {},
      "metadata": {
        "origin": "trust_policy"
      }
    }
  ]
}
```

## Phase 3: Attack Path Detection

Phase 3 consumes the serialized directed attack graph from Phase 2 and identifies valid multi-hop privilege escalation and lateral movement sequences from starting attacker entities (users) to target cloud resources.

### 1. Definition of an Attack Path
An attack path is an ordered sequence of graph relationships representing an attacker traversing between identities and cloud resources:
- **`source`**: The starting identity node (`user:<name>`).
- **`target`**: The destination resource node (`resource:<name>`).
- **`nodes`**: Ordered list of visited nodes along the path.
- **`edges`**: Ordered list of traversed edges, retaining full IAM security metadata (`actions`, `resources`, `conditions`, `origin`).
- **`hop_count`**: Number of edges in the path (`len(nodes) - 1`). Multi-hop paths have `hop_count >= 2`.
- **`conditional`**: Boolean flag set to `true` if at least one traversed edge has non-empty conditions.

### 2. Traversal Semantics (`path/traversal_policy.py`)
- **`CAN_ASSUME`**: A valid identity pivot. The attacker assumes the target role and gains the ability to traverse its outbound permissions.
- **`CAN_PASS_ROLE`**: Semantically distinct from `CAN_ASSUME`. A role possessing `CAN_PASS_ROLE` alone **cannot** assume the target role or execute its outbound permissions.
- **`CAN_ACCESS` / `CAN_MODIFY`**: Valid transitions to reach destination cloud resources (read or write).
- **`Allow` vs. `Deny`**: Only `Allow` edges represent attacker capabilities. Explicit `Deny` edges are **never** traversed.
- **Conditions**: Conditions are preserved verbatim on edges. Paths with conditions are flagged `conditional: true` without attempting runtime evaluation.

### 3. Path Enumeration & Simple Paths (`path/path_finder.py`)
- **Simple Paths**: A node may not appear more than once within a single path, guaranteeing cycle safety and eliminating infinite loops.
- **Max-Hop Bound**: Configurable bound (`--max-hops`, default: 5) to prevent unbounded enumeration.
- **Deterministic Traversal**: Candidate edges and sources are sorted deterministically, ensuring bit-identical path generation.

### 4. Decoupled Path Filtering (`path/path_filter.py`)
Paths can be filtered without re-running traversal:
- `--min-hops <n>`: e.g., `2` for multi-hop paths.
- `--max-hops <n>`: Upper bound on path length.
- `--source <id>`: Specific starting node (e.g. `user:InitialUser`).
- `--target <id>`: Specific destination node (e.g. `resource:ProductionDataBucket`).
- `--edge-types <types...>`: Filter paths containing specific edge types.

### 5. Path Output Schema (`path/path_serializer.py`)
```json
{
  "scenario_id": "scenario_009",
  "source_filter": "user:InitialUser",
  "target_filter": "resource:ProductionDataBucket",
  "max_hops": 5,
  "total_paths": 2,
  "paths": [
    {
      "path_id": "scenario_009_path_001",
      "scenario_id": "scenario_009",
      "source": "user:InitialUser",
      "target": "resource:ProductionDataBucket",
      "nodes": [
        "user:InitialUser",
        "role:IntermediateRoleA",
        "role:TargetRoleB",
        "resource:ProductionDataBucket"
      ],
      "edges": [ ... ],
      "hop_count": 3,
      "conditional": false,
      "edge_types": [
        "CAN_ASSUME",
        "CAN_ASSUME",
        "CAN_ACCESS"
      ]
    }
  ]
}
```

---

## Phase 4: Path Feature Extraction

Phase 4 converts each Phase 3 attack path into a flat, deterministic feature vector consumed by everything downstream (Phase 5's labeling rules, Phase 6's models, Phase 7's SHAP explanations).

### 1. Feature Categories (`features/feature_schema.py`)

`FEATURE_NAMES` fixes a canonical, ordered list of ~45 features grouped into: path structure (`hop_count`, `role_count`, `user_count`, ...), edge-type counts (`assume_count`, `has_passrole`, ...), permission breadth (`wildcard_action_count`, `has_wildcard_resource`, ...), trust/principal features (`external_principal_count`, `has_wildcard_principal`, ...), condition features, effect counts, target metadata (`target_sensitive`, `target_criticality`), and composition ratios (`role_hop_ratio`, `assume_ratio`, ...).

### 2. Extraction (`features/feature_extractor.py`)

`extract_features(path: dict) -> dict` takes one Phase 3 path dict and returns `{"scenario_id", "path_id", "source", "target", "features": {...}}`, where `features` matches `FEATURE_NAMES` exactly. Trust-principal features (`external_principal_count`, etc.) read `edge["metadata"]["principal_type"]`, which `graph_builder.py` tags as `"internal"`, `"service"`, `"external"`, or `"wildcard"` on every `CAN_ASSUME` edge.

### Phase 4 CLI
```bash
python -m features.main output/scenario_009_paths.json --output output/scenario_009_features.json
python -m features.main output/scenario_009_paths.json --format csv --output output/scenario_009_features.csv
```

---

## Phase 5: Synthetic Dataset Generation

Phase 5 generates a large, labeled dataset of attack paths for ML training, since real AWS IAM configurations aren't used in this project. It runs the full Phase 1→4 pipeline in-process (no file round-trips) over synthetic, randomly generated IAM scenarios.

### 1. Scenario Library (`dataset/scenario_library.py`)

Nine deterministic scenario templates, one per attack pattern: `read_only` (LOW), `wildcard_s3` (MEDIUM), `pass_role_escalation`, `assume_role_chain`, `long_chain` (HIGH), `external_trust_critical`, `policy_modification`, `cross_account_wildcard`, `admin_wildcard` (CRITICAL). Each is built from small composable pieces in `dataset/entity_factory.py` (random user/role/resource names, trust statements, permission statements) and returns `(raw_scenario, meta)`, where `meta` records which resources are sensitive and which roles need to be probed as explicit `iam:PassRole` targets (since `iam:PassRole` alone never reaches an auto-discovered resource target -- see `path/traversal_policy.py`).

### 2. Orchestration (`dataset/generator.py`)

For each of `--count` scenarios: pick a scenario type (weighted so the four risk labels come out roughly even), build it, and run it through `parser.normalizer` → `graph.graph_builder` → `path.path_finder` → `features.feature_extractor`, assembling one labeled row per discovered attack path. Deterministic for a fixed `--seed` (default `42`, matching CLAUDE.md's `random_state = 42`).

### 3. Ground-Truth Labeling (`dataset/label_generator.py`)

A pure function `classify(row) -> (risk_label, risk_score, attack_type, risk_cause)`. Priority order is CRITICAL → HIGH → MEDIUM → LOW: CRITICAL for `admin_permission`, `external_trust`, `cross_account`, `policy_modification`, or (`wildcard_action` **and** `sensitive_target`); HIGH for `pass_role`, an `assume_role` chain (`role_count >= 2`), a long path (`path_length >= 4`), or a sensitive target reached; MEDIUM for any wildcard; otherwise LOW.

### 4. Dataset Schema (`dataset/schema.py`)

```
scenario_id, path_id, source_identity, target_resource, path_length, role_count,
user_count, assume_role, pass_role, wildcard_action, wildcard_resource,
policy_modification, external_trust, cross_account, sensitive_target,
admin_permission, risk_label, risk_score, attack_type, risk_cause
```

### Phase 5 CLI
```bash
python -m dataset.main --count 5000 --seed 42 --output data/processed/iam_attack_dataset.csv
```

---

## Phase 6: Machine Learning Risk Assessment

Phase 6 trains supervised classifiers on the Phase 5 dataset to predict `risk_label` for unseen attack paths.

### 1. Preprocessing (`models/preprocess.py`)

Loads the CSV, derives `target_type` from the `target_resource` node-id prefix (`user:`/`role:`/`resource:`), one-hot encodes `attack_type`/`target_type`, and splits 70/15/15 (train/val/test), stratified on `risk_label`, `random_state = 42`.

### 2. Training (`models/train.py`)

Trains Logistic Regression and Random Forest (scikit-learn) plus XGBoost when its native library is importable in the current environment; each model is saved to `models/<name>.pkl` via `joblib`, along with `models/feature_columns.pkl` (the exact column order needed for inference).

### 3. Evaluation (`models/evaluate.py`)

Computes accuracy, weighted precision/recall/F1, weighted ROC-AUC, a confusion matrix, a full classification report, and (for Random Forest) feature importances -- written to `evaluation/model_metrics.json`.

### Phase 6 CLI
```bash
python -m models.train --input data/processed/iam_attack_dataset.csv
python -m models.predict --path-id <path_id from the CSV>
```

Example `predict` output:
```json
{
  "path_id": "synthetic_00005_path_001",
  "predicted_label": "CRITICAL",
  "predicted_score": 1.0,
  "confidence": 0.9971
}
```

---

## Phase 7: Explainable AI Using SHAP

Phase 7 explains every Random Forest prediction with per-feature SHAP contributions.

### 1. Explainer (`explainability/shap_explainer.py`)

Wraps `shap.TreeExplainer` around the saved Random Forest -- Random Forest is the designated explainability model (CLAUDE.md section 6.3); tree ensembles need no background dataset.

### 2. Local Explanations (`explainability/explain_prediction.py`)

`explain_path(path_id)` returns the top 6 SHAP contributors for that path's predicted class:
```json
{
  "path_id": "synthetic_00005_path_001",
  "prediction": "CRITICAL",
  "top_factors": [
    {"feature": "policy_modification", "impact": 0.1059},
    {"feature": "role_count", "impact": 0.0839}
  ]
}
```

### 3. Plots (`explainability/visualize.py`)

Global summary and feature-importance bar plots (averaged across all four risk classes), plus local waterfall/force/decision plots for one path -- all saved under `evaluation/shap/`.

### Phase 7 CLI
```bash
python -m explainability.export_explanation --path-id <path_id>
python -m explainability.export_explanation --all --output evaluation/shap/explanations.json
```

### What Phases 5-7 Do Not Do

- Detect attacks in progress, or analyze live logs/CloudTrail (this is a posture-assessment tool: it scores latent risk in a *given* IAM configuration, not runtime activity)
- Map a prediction's top SHAP factor back onto a specific graph edge as a single "choke point" (Phase 8, planned)
- Generate plain-language remediation text (Phase 9, planned)
- Provide any visual dashboard (Phase 10, planned)

---

## Running the Project

### Setup
```bash
pip3 install --user -r requirements.txt
```

### Phase 1 Parser CLI
```bash
python -m parser.main data/scenarios/scenario_001.json --output output/scenario_001_normalized.json
```

### Phase 2 Graph Builder CLI
```bash
python -m graph.main output/scenario_001_normalized.json --output output/scenario_001_graph.json
```

### Phase 3 Path Detection CLI
```bash
# Detect all paths from automatic user sources to all resources:
python -m path.main output/scenario_009_graph.json --output output/scenario_009_paths.json

# Detect paths for a specific source and target with max hops:
python -m path.main output/scenario_009_graph.json \
    --source user:InitialUser \
    --target resource:ProductionDataBucket \
    --max-hops 5 \
    --output output/scenario_009_paths.json

# Filter for multi-hop paths only (min 2 hops):
python -m path.main output/scenario_009_graph.json --min-hops 2 --output output/scenario_009_multihop_paths.json
```

### Phase 4 Feature Extraction CLI
```bash
python -m features.main output/scenario_009_paths.json --output output/scenario_009_features.json
```

### Phase 5 Dataset Generation CLI
```bash
python -m dataset.main --count 5000 --output data/processed/iam_attack_dataset.csv
```

### Phase 6 Model Training & Prediction CLI
```bash
python -m models.train --input data/processed/iam_attack_dataset.csv
python -m models.predict --path-id <path_id from the CSV>
```

### Phase 7 Explainability CLI
```bash
python -m explainability.export_explanation --path-id <path_id>
```

### Running Automated Tests
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## Phase 3 Scope & Boundaries

Phase 3 is strictly dedicated to graph path enumeration, simple path discovery, traversal policy enforcement, and path filtering.

Phase 3 **DOES NOT**:
- Calculate risk scores or attack path probabilities
- Rank, sort, or prioritize paths by "severity" or "danger"
- Extract ML features or train machine learning models
- Generate SHAP or XAI feature attributions
- Generate remediation actions or playbooks
- Connect to AWS live accounts or APIs
- Provide a web frontend or GUI

Risk assessment, feature extraction, ML training, and XAI explanations are Phases 4-7 (all now complete, documented above). Choke-point detection, remediation, and dashboarding are Phases 8-10, planned but not yet implemented.