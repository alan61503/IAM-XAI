# Explainable Attack Path Risk Assessment for Cloud Identity Configurations

## Phase 1: IAM Configuration Parsing and Normalization

Phase 1 provides a robust, modular Python parser that ingests synthetic AWS IAM configuration JSON files and normalizes them into a standardized, deterministic representation of cloud entities, permissions, and trust relationships.

The output produced by Phase 1 serves as the clean structured input for Phase 2, where an attack graph engine will construct relationship edges and graph topologies.

---

## 1. What Phase 1 Does

- **Validates Synthetic IAM JSON**: Verifies structural correctness, required fields, and policy statement types.
- **Normalizes Permissions**: Converts single or multiple actions/resources into uniform arrays while preserving `Effect` (`Allow` / `Deny`), conditions, and exact wildcard tokens (`*`, `s3:*`, `arn:aws:s3:::*`).
- **Normalizes Trust Relationships**: Parses role trust policies across diverse principal types (`AWS`, `Service`, wildcards), generating structured principal-to-role relationships.
- **Extracts Standard Entities**: Identifies and catalogs users, roles, resources, and optional groups.
- **Strictly Preserves Security Information**: Retains conditions, wildcards, and Deny rules without filtering or lossy simplification.

---

## 2. Input Format

Scenarios are represented in synthetic IAM configuration JSON format:

```json
{
  "scenario_id": "scenario_001",
  "description": "Basic IAM configuration",
  "users": [
    {
      "name": "UserA"
    }
  ],
  "roles": [
    {
      "name": "RoleA",
      "trust_policy": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {
              "AWS": "UserA"
            },
            "Action": "sts:AssumeRole"
          }
        ]
      },
      "permissions": [
        {
          "Effect": "Allow",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::example-bucket/*"
        }
      ]
    }
  ],
  "resources": [
    {
      "name": "ExampleBucket",
      "type": "s3",
      "arn": "arn:aws:s3:::example-bucket"
    }
  ]
}
```

---

## 3. Output Format

The parser transforms the configuration into a normalized JSON structure:

```json
{
  "scenario_id": "scenario_001",
  "entities": [
    {
      "type": "user",
      "name": "UserA"
    },
    {
      "type": "role",
      "name": "RoleA"
    },
    {
      "type": "resource",
      "name": "ExampleBucket",
      "arn": "arn:aws:s3:::example-bucket",
      "resource_type": "s3"
    }
  ],
  "permissions": [
    {
      "source": "RoleA",
      "effect": "Allow",
      "actions": [
        "s3:GetObject"
      ],
      "resources": [
        "arn:aws:s3:::example-bucket/*"
      ],
      "conditions": {}
    }
  ],
  "trust_relationships": [
    {
      "source": "UserA",
      "effect": "Allow",
      "actions": [
        "sts:AssumeRole"
      ],
      "target": "RoleA",
      "conditions": {}
    }
  ]
}
```

---

## 4. Supported Fields and Constructs

| Field / Construct | Handling / Normalization |
| :--- | :--- |
| **Users** | Extracted as entity `{"type": "user", "name": "..."}` |
| **Roles** | Extracted as entity `{"type": "role", "name": "..."}` |
| **Resources** | Extracted as entity `{"type": "resource", "name": "...", "arn": "...", "resource_type": "..."}` |
| **Groups** | Extracted as entity `{"type": "group", "name": "..."}` (when defined) |
| **Actions** | Single string (`"s3:GetObject"`) or array (`["s3:GetObject", ...]`) normalized to list of strings |
| **Resources** | Single string or array normalized to list of strings |
| **Effects** | Preserves `"Allow"` and `"Deny"` (with case normalization) |
| **Principals** | Supports `AWS` (string, list, or wildcard `*`), `Service` (e.g. `ec2.amazonaws.com`), and direct wildcard `*` |
| **Conditions** | Preserves full condition blocks as JSON dictionaries (`conditions: {}` when absent) |
| **Wildcards** | Preserves `*`, `s3:*`, `arn:aws:s3:::*` exactly as specified |
| **Statements** | Handles single statement object or array of statement objects |

---

## 5. Running the Parser

### CLI Entrypoint

Parse a scenario and print normalized JSON to standard output:
```bash
python -m parser.main data/scenarios/scenario_001.json
```

Parse a scenario and save normalized JSON to a file:
```bash
python -m parser.main data/scenarios/scenario_001.json --output output/scenario_001_normalized.json
```

### Python API

```python
from parser import normalize_scenario_file

normalized_data = normalize_scenario_file("data/scenarios/scenario_001.json")
print(normalized_data["entities"])
```

---

## 6. Running Tests

Run the full automated test suite using Python's built-in `unittest` runner:
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

If `pytest` is installed:
```bash
pytest -v
```

---

## 7. Scope & Phase 1 Boundary

Phase 1 is strictly dedicated to parsing and configuration normalization. Phase 1 **DOES NOT**:
- Build attack graphs or topologies
- Detect attack paths or privilege escalation chains
- Calculate vulnerability or risk scores
- Train machine learning models
- Generate SHAP or XAI explanations
- Generate remediation actions or playbooks
- Connect to AWS live accounts or AWS APIs
- Provide a web frontend or GUI

All graph construction and risk modeling are deferred to subsequent phases.