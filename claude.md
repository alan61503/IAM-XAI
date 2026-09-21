# IAM-XAI — Project Context & Implementation Roadmap (Phases 5–7)

**Project:** IAM-XAI (Identity and Access Management Explainable AI)

**Version:** v1.0 – Research Engine Roadmap

**Owner:** Team IAM-XAI

**Current Milestone:** Phase 8 (Choke Point Detection) — Phases 5-7 complete

**Repository Purpose:** Simulate AWS IAM environments outside AWS and build an Explainable AI system capable of identifying, scoring, and explaining IAM privilege escalation attack paths.

---

# 1. Project Vision

IAM-XAI is a cybersecurity research project that models Identity and Access Management (IAM) environments as attack graphs, discovers privilege escalation paths, predicts the security risk of those paths using machine learning, and explains every prediction using Explainable AI (SHAP).

The project intentionally avoids interacting with real AWS accounts during development. Instead, it generates realistic synthetic IAM configurations that mimic AWS IAM behavior.

**End-to-End Pipeline**

IAM Configuration
↓
Parser
↓
Structured Relationships
↓
Attack Graph
↓
Attack Path Discovery
↓
Feature Extraction
↓
Synthetic Dataset Generation
↓
ML Risk Prediction
↓
SHAP Explanation
↓
(Phase 8+) Choke Point Detection
↓
(Phase 9+) Remediation Suggestions
↓
(Phase 10+) Dashboard

---

# 2. Project Scope

## Included

- Synthetic IAM configurations.
- IAM policy parsing.
- Trust relationship modeling.
- Graph-based privilege escalation.
- Supervised ML risk scoring.
- SHAP explainability.
- Research evaluation metrics.

## Excluded (Current Version)

- Live AWS credentials.
- AWS SDK integration.
- Terraform deployment.
- IAM policy modification.
- Real cloud resources.

---

# 3. Architecture Overview

```
iam-xai/
│
├── data/
│   ├── raw/
│   ├── synthetic/
│   ├── processed/
│   └── features/
│
├── parser/                  # Phase 1
├── graph/                   # Phase 2
├── attack_paths/            # Phase 3
├── features/                # Phase 4
│
├── dataset/                 # Phase 5
│
├── models/                  # Phase 6
│
├── explainability/          # Phase 7
│
├── evaluation/
│
├── notebooks/
│
├── configs/
│
├── tests/
│
├── docs/
│
└── CLAUDE.md
```

---

# 4. Phase Completion Status

| Phase | Status | Output |
|--------|--------|--------|
| Phase 1 | ✅ Complete | Structured IAM relationships |
| Phase 2 | ✅ Complete | Attack graph |
| Phase 3 | ✅ Complete | Attack paths |
| Phase 4 | ✅ Complete | Feature vectors |
| Phase 5 | ✅ Complete | Synthetic research dataset |
| Phase 6 | ✅ Complete | Risk prediction model |
| Phase 7 | ✅ Complete | SHAP explanations |
| Phase 8 | ✅ Complete | Choke point detection |
| Phase 9 | ✅ Complete | Remediation engine |
| Phase 10 | ✅ Complete | Dashboard |

---

# 5. Inputs Available From Previous Phases

Phase 4 produces a feature vector for every attack path.

Example:

```json
{
  "path_id": 17,
  "path_length": 4,
  "role_count": 2,
  "resource_count": 1,
  "contains_assume_role": true,
  "contains_pass_role": true,
  "contains_wildcard_action": true,
  "contains_wildcard_resource": false,
  "external_trust": true,
  "cross_account": false,
  "policy_modification": true,
  "sensitive_target": true,
  "target_type": "S3_BUCKET"
}
```

This becomes the **single source of truth** for Phases 5–7.

---

# PHASE 5 — Synthetic Dataset Generation

# Objective

Generate thousands of realistic IAM attack scenarios with known ground truth labels.

The dataset is the foundation of the ML research.

---

## Deliverables

- Synthetic IAM configurations.
- Attack paths.
- Feature vectors.
- Risk labels.
- Risk causes.

Output file:

```
data/processed/iam_attack_dataset.csv
```

---

# Phase 5 Pipeline

Synthetic IAM Generator
↓
IAM Configuration
↓
Parser
↓
Attack Graph
↓
Attack Path Discovery
↓
Feature Extraction
↓
Label Generator
↓
Dataset

---

# 5.1 Dataset Schema

Every row represents **one attack path**.

| Column | Description |
|--------|-------------|
| scenario_id | Synthetic environment ID |
| path_id | Unique attack path ID |
| source_identity | Starting identity |
| target_resource | Final resource |
| path_length | Number of hops |
| role_count | Roles traversed |
| user_count | Users traversed |
| assume_role | Binary feature |
| pass_role | Binary feature |
| wildcard_action | Binary feature |
| wildcard_resource | Binary feature |
| policy_modification | Binary feature |
| external_trust | Binary feature |
| cross_account | Binary feature |
| sensitive_target | Binary feature |
| admin_permission | Binary feature |
| risk_label | LOW / MEDIUM / HIGH / CRITICAL |
| risk_score | Numeric score |
| attack_type | Privilege Escalation / Lateral Movement / Data Access |
| risk_cause | Primary reason |

---

# 5.2 Synthetic IAM Generator

Purpose:

Create randomized IAM environments without AWS.

## Entities

Generate random combinations of:

- Users
- Roles
- Groups
- S3 Buckets
- DynamoDB Tables
- Lambda Functions
- EC2 Instances
- Secrets Manager
- KMS Keys

Example ranges:

| Entity | Count |
|--------|------:|
| Users | 3–20 |
| Roles | 2–15 |
| Resources | 5–30 |
| Policies | 5–50 |

---

## Permissions to Randomize

Actions:

- AssumeRole
- PassRole
- GetObject
- PutObject
- ListBucket
- InvokeFunction
- ReadSecret
- WriteSecret
- ModifyPolicy
- AttachRolePolicy
- IAMAdmin
- Wildcard *

Resources:

- Specific ARN.
- Wildcard resource.
- Sensitive resources.

Trust Policies:

- Internal trust.
- External trust.
- Cross-account trust.
- Federated principals.

---

# 5.3 Attack Scenario Library

The generator must intentionally inject attack patterns.

| Scenario | Label |
|----------|-------|
| Read-only access | LOW |
| Wildcard S3 access | MEDIUM |
| PassRole escalation | HIGH |
| AssumeRole chain | HIGH |
| External trust to sensitive role | CRITICAL |
| IAM Policy modification | CRITICAL |
| Cross-account wildcard trust | CRITICAL |
| Long privilege escalation chain | HIGH |

Minimum goal:

**1,000 scenarios**

Stretch goal:

**5,000–10,000 attack paths**

---

# 5.4 Ground Truth Labeling Rules

Risk labels should be deterministic.

## LOW

- Read-only permissions.
- No sensitive target.
- No escalation.

## MEDIUM

- Wildcard action OR wildcard resource.
- Limited sensitive access.

## HIGH

- PassRole.
- AssumeRole chain.
- Multiple hops.
- Sensitive target reached.

## CRITICAL

- IAM administrative permissions.
- External trust.
- Cross-account escalation.
- Policy modification permissions.
- Wildcard + sensitive resource combination.

---

# 5.5 Success Criteria

- Deterministic labels.
- Balanced class distribution.
- CSV exports successfully.
- Every path has an explanation cause.

Deliverables

- `dataset/generator.py`
- `dataset/scenario_library.py`
- `dataset/label_generator.py`

---

# PHASE 6 — Machine Learning Risk Assessment

# Objective

Predict the risk level of an attack path from engineered path features.

Input:

Feature vector.

Output:

Risk score and risk class.

---

# 6.1 ML Workflow

Dataset
↓
Preprocessing
↓
Train/Test Split
↓
Model Training
↓
Evaluation
↓
Saved Model

---

# 6.2 Feature Set

Numeric Features

- path_length
- role_count
- user_count
- resource_count

Binary Features

- assume_role
- pass_role
- wildcard_action
- wildcard_resource
- policy_modification
- admin_permission
- external_trust
- cross_account
- sensitive_target

Categorical Features

- attack_type
- target_type

---

# 6.3 Model Candidates

Train three supervised models.

| Model | Purpose |
|-------|---------|
| Logistic Regression | Baseline interpretable model |
| Random Forest | Non-linear decision model |
| XGBoost | High-performance ensemble model |

Random Forest is expected to be the primary explainability model.

---

# 6.4 Dataset Split

Recommended:

- Train — 70%
- Validation — 15%
- Test — 15%

Use a fixed random seed.

```python
random_state = 42
```

---

# 6.5 Evaluation Metrics

Classification Metrics

- Accuracy
- Precision
- Recall
- F1 Score
- ROC-AUC

Additional Outputs

- Confusion Matrix.
- Classification Report.
- Feature Importance (Random Forest).

---

# 6.6 Model Output Format

Example prediction:

```json
{
  "path_id": 17,
  "predicted_label": "HIGH",
  "predicted_score": 0.89,
  "confidence": 0.93
}
```

---

# 6.7 Saved Artifacts

```
models/
│
├── train.py
├── predict.py
├── preprocess.py
├── random_forest.pkl
├── logistic_regression.pkl
└── xgboost.pkl
```

---

# 6.8 Success Criteria

- Three trained models.
- Saved models.
- Evaluation report generated.
- Test metrics exported.

Output:

```
evaluation/model_metrics.json
```

---

# PHASE 7 — Explainable AI Using SHAP

# Objective

Explain WHY a machine learning model predicted a specific attack path as risky.

The explanation must identify which IAM characteristics contributed most to the prediction.

---

# 7.1 Explainability Pipeline

Feature Vector
↓
Random Forest Model
↓
Prediction
↓
SHAP Explainer
↓
Feature Contributions

---

# 7.2 SHAP Explainer

Preferred explainer:

TreeExplainer

Reason:

Compatible with Random Forest and XGBoost.

---

# 7.3 Explanation Output

Example:

Prediction:

Critical Risk

Feature Contributions

| Feature | SHAP Contribution |
|---------|------------------:|
| external_trust | +0.28 |
| wildcard_action | +0.24 |
| pass_role | +0.21 |
| sensitive_target | +0.16 |
| path_length | +0.05 |
| role_count | +0.03 |

---

# 7.4 Visualization Deliverables

Global Explanations

- SHAP Summary Plot.
- Feature Importance Bar Plot.

Local Explanations

- Waterfall Plot.
- Force Plot.
- Decision Plot.

All plots should be saved.

```
evaluation/shap/
```

---

# 7.5 Explanation API Output

```json
{
  "path_id": 17,
  "prediction": "CRITICAL",
  "top_factors": [
    {
      "feature": "external_trust",
      "impact": 0.28
    },
    {
      "feature": "wildcard_action",
      "impact": 0.24
    },
    {
      "feature": "pass_role",
      "impact": 0.21
    }
  ]
}
```

---

# 7.6 Success Criteria

- Every prediction has SHAP values.
- Top contributing features identified.
- Explanation exported as JSON.
- Plots generated automatically.

Files:

```
explainability/
│
├── shap_explainer.py
├── explain_prediction.py
├── visualize.py
└── export_explanation.py
```

---

# Integration Between Phases 5–7

| Phase | Input | Output |
|-------|-------|--------|
| Phase 5 | Feature vectors | Dataset CSV |
| Phase 6 | Dataset CSV | Risk prediction model |
| Phase 7 | Trained model + feature vector | SHAP explanation |

The output of each phase becomes the input of the next phase.

---

# Research Deliverables

## Dataset

- CSV dataset.
- Scenario metadata.
- Label distribution report.

## ML

- Model comparison.
- Metrics report.
- Confusion matrix.

## Explainability

- SHAP plots.
- Explanation JSON.
- Top feature rankings.

These outputs will later be referenced in the IEEE research paper.

---

# Coding Standards

## Python Version

Python 3.11+

## Style Guide

- Type hints required.
- Dataclasses where appropriate.
- Modular functions.
- No duplicated logic.
- Random seed fixed for reproducibility.

## Folder Responsibilities

| Folder | Responsibility |
|--------|----------------|
| dataset | Synthetic environment generation |
| models | Training and prediction |
| explainability | SHAP computation and visualization |
| evaluation | Metrics and experiment outputs |
| tests | Unit tests for generator and ML pipeline |

---

# Milestone Checklist

## Phase 5 — Dataset

- [x] Synthetic IAM generator implemented.
- [x] Scenario library created.
- [x] Automatic risk labeling implemented.
- [x] Dataset exported to CSV.
- [x] Dataset statistics generated.

## Phase 6 — ML

- [x] Preprocessing pipeline completed.
- [x] Logistic Regression trained.
- [x] Random Forest trained.
- [x] XGBoost trained. (wired in and auto-included whenever its native library loads; gracefully skipped otherwise)
- [x] Evaluation metrics generated.
- [x] Best model saved.

## Phase 7 — SHAP

- [x] TreeExplainer implemented.
- [x] Local explanation generated.
- [x] Global explanation generated.
- [x] SHAP plots exported.
- [x] Explanation JSON exported.

---

# Phase 8+ Context (Do Not Implement Yet)

Future phases consume SHAP outputs.

**Phase 8** identifies the permission edge with the highest SHAP contribution and maps it back to the attack graph as a choke point.

**Phase 9** converts choke points into human-readable remediation recommendations.

**Phase 10** visualizes attack graphs, risk scores, SHAP explanations, choke points, and remediation in an interactive dashboard.

Phase 7 is now fully functional, so Phase 8 is unblocked. No code for Phase 9 or 10 should be introduced before Phase 8 is fully functional.

---

# Definition of Done (Phase 5-7 — Complete)

The research engine is complete through Phase 7:

- [x] A synthetic IAM environment can be generated.
- [x] Attack paths are automatically labeled with ground-truth risk.
- [x] A machine learning model predicts the risk category of unseen attack paths.
- [x] SHAP explains every prediction with feature-level attribution.
- [x] All outputs are reproducible and exported for evaluation and inclusion in the research paper.

See `README.md` for how each phase works, its CLI commands, and expected output.