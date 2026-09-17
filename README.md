# Explainable Attack Path Risk Assessment for Cloud Identity Configurations

This project implements an end-to-end framework for analyzing, modeling, and explaining security risk across cloud identity configurations (IAM).

---

## Architecture Overview

- **Phase 1: IAM Configuration Parsing and Normalization** (Completed)
- **Phase 2: Attack Graph Construction** (Completed)
- **Phase 3: Attack Path Traversal & Detection** (Completed)
- **Phase 4: Path Feature Extraction** (Future)
- **Phase 5: Machine Learning Risk Assessment** (Future)
- **Phase 6: Explainable AI (XAI / SHAP)** (Future)
- **Phase 7: Remediation Engine & Verification** (Future)

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
- Conditions are not evaluated during Phase 2; they are preserved as first-class edge metadata for path feature extraction (Phase 4) and explanation (Phase 6).

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

## Running the Project

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

All risk assessment, feature extraction, ML training, and XAI explanations belong to Phase 4 and beyond.