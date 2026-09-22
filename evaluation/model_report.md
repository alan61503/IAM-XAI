# Phase 6 Model Report

Dataset: 76479 attack paths from 3000 environments (2068 distinct feature vectors). Splits grouped by scenario.

- Label distribution: {'LOW': 20049, 'MEDIUM': 21929, 'HIGH': 19598, 'CRITICAL': 14903}
- Label-ambiguity ceiling (best achievable accuracy): 0.891
- Test rows whose exact feature vector also occurs in train: 98.2%

## Held-out test set

| Model | Accuracy | Balanced acc. | Macro F1 | Weighted F1 | ROC-AUC (macro OvR) | Severe-miss rate |
|---|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.753 | 0.761 | 0.765 | 0.754 | 0.914 | 12.9% |
| random_forest | 0.879 | 0.879 | 0.881 | 0.879 | 0.974 | 9.8% |
| xgboost | 0.882 | 0.881 | 0.884 | 0.882 | 0.979 | 10.4% |
| random_forest+escalation_floor | 0.878 | 0.878 | 0.880 | 0.878 | n/a | 9.8% |
| rule_based_baseline | 0.421 | 0.420 | 0.390 | 0.387 | n/a | 13.5% |

## 95% confidence intervals (grouped bootstrap, 1000 resamples of test scenarios)

| Model | Accuracy 95% CI | Macro F1 95% CI | Macro F1 gap to RF (95% CI) | McNemar p vs RF |
|---|---|---|---|---|
| logistic_regression | [0.741, 0.764] | [0.753, 0.776] | [+0.105, +0.128] | 5.6e-204 |
| random_forest | [0.867, 0.889] | [0.870, 0.891] | – | – |
| xgboost | [0.871, 0.892] | [0.874, 0.894] | [-0.006, -0.001] | 0.0055 |
| random_forest+escalation_floor | [0.866, 0.888] | [0.869, 0.890] | [+0.000, +0.001] | 0.0039 |
| rule_based_baseline | [0.406, 0.435] | [0.371, 0.409] | [+0.471, +0.511] | 0 |

## Grouped 5-fold cross-validation (train+val)

| Model | Accuracy | Macro F1 |
|---|---:|---:|
| logistic_regression | 0.742 ± 0.004 | 0.754 ± 0.003 |
| random_forest | 0.882 ± 0.003 | 0.884 ± 0.004 |
| xgboost | 0.887 ± 0.003 | 0.889 ± 0.003 |

## Leave-one-pattern-out (Random Forest vs. hybrid with escalation floor)

Severe miss = a truly HIGH/CRITICAL path rated LOW/MEDIUM.

| Held-out pattern | Test paths | RF accuracy | Hybrid accuracy | RF severe-miss rate | Hybrid severe-miss rate |
|---|---:|---:|---:|---:|---:|
| wildcard_action | 1501 | 0.761 | 0.761 | 1.3% | 1.3% |
| wildcard_resource | 6363 | 0.885 | 0.885 | 11.0% | 11.0% |
| pass_role | 983 | 0.087 | 0.395 | 96.8% | 0.0% |
| assume_chain | 3721 | 0.906 | 0.902 | 7.2% | 7.2% |
| external_trust | 546 | 0.665 | 0.665 | 14.3% | 14.3% |
| cross_account | 537 | 0.762 | 0.762 | 11.5% | 11.5% |
| wildcard_trust | 1752 | 0.569 | 0.569 | 22.0% | 22.0% |
| policy_modification | 760 | 0.670 | 0.737 | 8.4% | 0.0% |
| admin_wildcard | 2602 | 0.205 | 0.344 | 57.9% | 0.0% |

## Selected hyperparameters

- **logistic_regression**: `{'C': 10.0}` (validation macro F1 0.757)
- **random_forest**: `{'max_depth': None, 'min_samples_leaf': 1, 'class_weight': None}` (validation macro F1 0.884)
- **xgboost**: `{'max_depth': 4, 'learning_rate': 0.1}` (validation macro F1 0.891)

## Random Forest feature importance (top 10)

| Feature | Importance |
|---|---:|
| classification_tag | 0.530 |
| sensitive_target | 0.133 |
| conditional_edge_count | 0.037 |
| condition_key_count | 0.034 |
| has_conditions | 0.031 |
| write_access | 0.029 |
| path_length | 0.021 |
| target_service_secretsmanager | 0.020 |
| wildcard_principal | 0.018 |
| role_count | 0.016 |
