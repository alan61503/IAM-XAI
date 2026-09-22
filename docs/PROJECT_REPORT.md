# IAM-XAI — Project Report: Codebase Review, Research Hardening and Evaluation

**Project:** IAM-XAI (Explainable AI for AWS IAM attack-path risk)
**Period covered:** September 2026 review-and-hardening cycle
**Status:** Phases 1–10 functional; full research evaluation complete; 222 automated tests passing

---

## 1. Summary

The project entered this cycle with all ten phases implemented and a clean modular architecture, but its research results could not be trusted: the machine-learning dataset contained only **9 distinct feature vectors**, labels were a fixed rule over the model's own inputs, and every model scored a meaningless **1.0 accuracy**. The dashboard also displayed hardcoded "SHAP" values rather than real explanations.

This cycle rebuilt the dataset and labeling so the learning task is genuine, introduced a rigorous evaluation protocol, fixed a set of correctness and security bugs, and added six research experiments that each answer a question a reviewer would ask. The headline outcomes:

| Question | Result |
|---|---|
| Risk classification on unseen environments | Random Forest macro F1 **0.881** (95% CI 0.870–0.891) vs. **0.390** for the original fixed rules; best achievable ≈ 0.891 |
| Unseen escalation patterns | Pure ML misses up to 97% of severe cases; the new **hybrid** model misses **0%** |
| SHAP explanation quality | Top SHAP feature names a true cause for **95%** of paths; measurably faithful to the model |
| Choke-point remediation | 3 cuts remove **52.3%** of real risk — 99% of the optimum (52.7%) |
| Robustness | Model ranking unchanged across 8 perturbed-assumption variants |
| Published attack techniques | **18/26** detected with **0/6** false alarms |

The project is now defensible for presentation at an undergraduate IEEE conference, with its limitations measured and documented rather than hidden. All numbers in this report come from [`evaluation/RESULTS.md`](../evaluation/RESULTS.md), which is regenerated from the raw result files.

---

## 2. Starting Point: Codebase Review

A full read of the ~8,000-line codebase gave this assessment:

| Area | Grade | Notes |
|---|---|---|
| Architecture / modularity | B+ | Clean phase-per-package design, library + CLI per phase, deterministic output, good test coverage |
| Correctness | C | Several bugs producing wrong results without errors |
| Research validity (Phases 5–7) | D | Degenerate dataset; accuracy of 1.0 meaningless |
| Performance | B now, won't scale | Fast only because scenarios were tiny |
| Reproducibility | C− | Unpinned dependencies; SHAP could not import; 2 failing tests |

### Key findings

**Research validity**
- 5,000 dataset rows reduced to **9 unique feature vectors** — one per scenario template, one path per scenario.
- Labels were deterministic rules over the same 12 features the model received, so the model could only relearn those rules.
- `attack_type`, produced by the labeler, was fed back in as a model feature and was the most important one — label leakage.
- The train/test split was by row, so test rows duplicated training rows.
- The spec called for 3–20 users and 2–15 roles per environment; the generator built 1 user and 1–3 roles.

**Correctness and security**
- The dashboard showed **hardcoded explanation factors**, not SHAP output, and the choke-point detector ranked edges using them.
- The dashboard computed features differently from training: three features it read did not exist, so they were always 0.
- Explicit `Deny` statements had no effect on attack paths.
- `features/__init__.py` declared exports but imported nothing.
- The choke-point `cross_account` check could never match; a `"policy"` substring test matched read-only actions like `iam:GetPolicy`.
- The dashboard had a **path traversal** vulnerability in `/api/scenario/<id>`, bound to all interfaces by default, allowed any origin, and returned stack traces to clients.

**Environment**
- Committed models were pickled with scikit-learn 1.9.1 and failed to load under 1.6.1.
- NumPy 2.4 broke `numba`, so SHAP could not be imported at all.

---

## 3. Work Completed

### 3.1 Dataset and ground-truth redesign (Phase 5)

| Before | After |
|---|---|
| 9 fixed templates, 1 path each | Randomized environments at spec size (3–20 users, 2–15 roles, 5–30 resources, 6 resource types) |
| Attack patterns in isolation | 0–3 of 9 attack patterns injected into a benign baseline; mitigations (MFA, SourceIp, ExternalId) and Deny guardrails |
| Labels = rules over model features | Labels from a **risk oracle**: `impact × (0.35 + 0.65 × likelihood)` using information the model sees only partially |
| Binary "sensitive" flag | True classification tier (hidden) + an imperfect `DataClassification` tag (85% coverage, 5% off by one tier) |
| 5,000 rows / 9 distinct vectors | **76,479 paths / 3,000 environments / 2,068 distinct vectors**, labels roughly balanced |

Supporting changes:
- **Shared feature builder** (`dataset/row_builder.py`) used by both training and the dashboard; a test proves they produce identical rows.
- **Per-environment seeding** makes generation reproducible and parallel: identical output for any worker count, about 5 seconds for 3,000 environments.
- **Class-balanced capping** at 30 paths per environment, so dense environments can't dominate.
- **`OracleConfig`** holds every oracle weight in one place, which enables the sensitivity analysis.
- The original CLAUDE.md §5.4 rules are kept as a **baseline** (`models/baselines.py`).

### 3.2 Evaluation protocol (Phase 6)

- **Split:** 70/15/15, grouped by environment, so no environment appears in two splits.
- **Tuning:** hyperparameters selected on the validation set; the chosen model is refit on train+validation and tested once.
- **Uncertainty and significance:**
  - grouped 5-fold cross-validation;
  - 95% confidence intervals by bootstrap-resampling whole test environments;
  - McNemar significance tests.
- **Security-relevant metric:** severe-miss rate, the share of truly HIGH/CRITICAL paths rated LOW/MEDIUM.
- **Generalisation:** leave-one-pattern-out testing on attack patterns absent from training.
- **Dataset diagnostics:** label-ambiguity ceiling (the best achievable accuracy) and train/test overlap.
- **XGBoost now trains:** it previously failed silently on string labels and is now wrapped in `LabelEncodedClassifier`.

### 3.3 Hybrid model

The generalisation test showed pure ML cannot recognise escalation primitives it never saw in training. The hybrid adds a small domain-knowledge floor to the Random Forest's output:

- admin-equivalent or policy-rewrite permission → at least **HIGH**;
- PassRole of a privileged role → at least **HIGH**;
- any other PassRole → at least **MEDIUM**.

A new visible feature, `target_privileged`, marks whether a role holds `*`/`iam:*` permissions, which an analyzer can read from the configuration. The hybrid matches the Random Forest's normal accuracy and removes every severe miss on unseen escalation patterns.

### 3.4 Correctness and security fixes

| Fix | Location |
|---|---|
| Explicit Deny now overrides Allow (action- and resource-aware; conditional denies conservatively ignored) | `path/traversal_policy.py`, `path/path_finder.py` |
| Dashboard uses real SHAP, the shared feature builder, batched predictions and cached models | `dashboard/server.py` |
| Path traversal blocked (id whitelist), localhost binding by default, CORS header removed, no stack traces to clients, 5 MB body limit, threaded server | `dashboard/server.py`, `dashboard/main.py` |
| Choke-point matchers rebuilt on shared definitions; `cross_account` fixed; read-only `iam:GetPolicy` no longer counts as policy modification | `choke_point/choke_finder.py` |
| Choke points weighted by severity (`expected_risk`) instead of prediction confidence | `models/predict.py`, `choke_point/choke_finder.py` |
| PassRole held directly by users now searched as a target | `dataset/row_builder.py` |
| `iam:AttachGroupPolicy` added to policy-modification actions | `dataset/path_signals.py` |
| `features` package exports fixed | `features/__init__.py` |
| Negative SHAP values shown with the correct sign | `dashboard/static/app.js` |

### 3.5 Research experiments

| Experiment | Module | Question |
|---|---|---|
| Explanation faithfulness | `explainability/faithfulness.py` | Do SHAP explanations name the true cause, and do they reflect what the model uses? |
| Choke-point evaluation | `choke_point/evaluate.py` | How much real risk does cutting IAM-XAI's choke points remove? |
| Sensitivity analysis | `experiments/sensitivity.py` | Do conclusions survive noise and changed oracle assumptions? |
| External benchmark | `experiments/benchmark.py` | Are independently documented attacks detected? |
| Figures | `experiments/figures.py` | Six publication figures (colour-blind-safe palette) |
| Results summary | `experiments/summary.py` | One consolidated, regenerable results document |

A greedy **budgeted choke-point selector** (`select_choke_point_set`) was added after the evaluation showed that picking the top-k edges independently wastes cuts on overlapping paths.

### 3.6 Performance and engineering

- **Dependencies:** exact versions pinned; a project virtual environment is documented.
- **Model files:** saved with compression (Random Forest 62 MB → 16 MB).
- **SHAP deduplication:** computed once per distinct feature vector, so explaining all 77k paths takes about 5 minutes instead of about 3 hours.
- **Parallel generation:** about 5 seconds for 3,000 environments.
- **Attack graph:** an adjacency index gives O(1) outgoing-edge lookup during path search.
- **Dashboard:** models load once per process, and predictions run in one batch instead of one per path.
- **Tests:** 182 → **222**, covering Deny semantics, parity between training and dashboard features, statistics, the hybrid floor, faithfulness helpers, greedy selection, sensitivity variants and benchmark validity.

---

## 4. Results

### RQ1 — Classification on unseen environments

| Model | Accuracy | Macro F1 [95% CI] | ROC-AUC | Severe-miss |
|---|---:|---|---:|---:|
| Logistic Regression | 0.753 | 0.765 [0.753, 0.776] | 0.914 | 12.9% |
| Random Forest | 0.879 | 0.881 [0.870, 0.891] | 0.974 | 9.8% |
| XGBoost | 0.882 | 0.884 [0.874, 0.894] | 0.979 | 10.4% |
| Hybrid (RF + escalation floor) | 0.878 | 0.880 [0.869, 0.890] | – | 9.8% |
| Static rules (baseline) | 0.421 | 0.390 [0.371, 0.409] | – | 13.5% |

- **Ceiling and stability:** the label-ambiguity ceiling is 0.891, so the tree models are near the limit of what these features allow. Grouped 5-fold cross-validation gives Random Forest macro F1 0.884 ± 0.004.
- **XGBoost vs Random Forest:** XGBoost's lead is statistically detectable but small (under 0.01 macro F1).
- **Against the baselines:** both tree models beat logistic regression and the rules by wide margins.

### RQ2 — Attack patterns never seen in training (severe-miss rate)

| Held-out pattern | Random Forest | Hybrid |
|---|---:|---:|
| PassRole | 96.8% | **0.0%** |
| Admin wildcard | 57.9% | **0.0%** |
| Policy modification | 8.4% | **0.0%** |
| Wildcard trust (`Principal: "*"`) | 22.0% | 22.0% |
| External trust | 14.3% | 14.3% |
| Cross-account | 11.5% | 11.5% |
| Wildcard resource | 11.0% | 11.0% |
| Assume-role chain | 7.2% | 7.2% |
| Wildcard action | 1.3% | 1.3% |

Structural patterns transfer to unseen environments. Escalation primitives do not, unless the domain-knowledge floor is added.

### RQ3 — Explanation quality (3,000 test paths)

| Ranking | Top-1 is a true cause | True causes in top 3 | Top 3 on multi-cause paths | Confidence drop, top 3 removed |
|---|---:|---:|---:|---:|
| SHAP (per path) | 95.3% | 90.5% | 77.0% | 0.537 |
| Global importance | 95.0% | 84.5% | 70.6% | 0.427 |
| Random ranking | 29.9% | 52.8% | 38.4% | 0.066 |

Per-path SHAP explanations recover more of the true causes than a one-size-fits-all ranking, especially on paths with several causes. They are also more faithful: removing SHAP's top features lowers the model's confidence the most.

### RQ4 — Choke-point remediation (200 unseen environments)

| Strategy | Risk removed, 1 cut | Risk removed, 3 cuts | Severe paths removed, 3 cuts |
|---|---:|---:|---:|
| Random edge | 7.2% | 20.0% | 20.8% |
| Most-shared edge (graph only) | 24.6% | 43.9% | 43.9% |
| IAM-XAI ranked | 25.8% | 46.6% | 50.1% |
| **IAM-XAI greedy** | **26.4%** | **52.3%** | **59.7%** |
| Oracle upper bound | 26.7% | 52.7% | 61.3% |

- **Gain over the graph-only baseline:** IAM-XAI greedy removes 7.3–9.7 points more risk with 3 cuts (95% CI).
- **Where the gain comes from:** an ablation without SHAP performs the same, so the improvement comes from ML risk weighting. SHAP's role is explaining *why* an edge matters, not selecting it.

### RQ5 — Robustness to oracle assumptions

Eight variants were tested: default, 5% and 10% label noise, three random ±20% weight perturbations, and cut points shifted ±10%. The ordering Random Forest > logistic regression ≫ static rules held in every variant. The Random Forest's macro F1 stayed within 0.02 of each variant's accuracy ceiling (largest gap 0.019).

### RQ6 — Independently documented attacks

The benchmark covers:
- the 21 IAM privilege-escalation methods catalogued by Rhino Security Labs;
- 5 scenarios modelled on CloudGoat descriptions and well-known trust misconfigurations;
- 6 benign controls.

| Result | Value |
|---|---|
| Attack paths discovered | 26/26 |
| Attacks rated HIGH/CRITICAL | **18/26 (69%)** |
| False alarms on benign controls | **0/6** |

The 8 misses are escalation mechanisms the graph does not model yet:
- credential takeover of another user;
- group-membership changes;
- rewriting the policy of a role the attacker can already assume;
- code injection into privileged services.

They were deliberately not patched after being seen, to avoid tuning to the test set.

### Before and after

| Metric | Before | After |
|---|---|---|
| Distinct feature vectors | 9 | 2,068 |
| Paths per environment | 1 | 25.5 (capped at 30) |
| Test split | By row (duplicates leak) | By environment |
| Reported accuracy | 1.0 (meaningless) | 0.879, near the 0.891 ceiling |
| Baseline comparison | None | Fixed rules: 0.390 macro F1 |
| Confidence intervals / significance | None | Grouped bootstrap, McNemar, 5-fold CV |
| Explanations in the dashboard | Hardcoded | Real SHAP, faithfulness measured |
| External validation | None | 26 published attack scenarios + 6 benign controls |
| Tests | 182 (2 failing, SHAP suite not importable) | 222 passing |

---

## 5. Limitations and Threats to Validity

1. **Synthetic ground truth.** Labels come from an oracle designed by the team, so the models learn to approximate it. Mitigations:
   - the oracle uses information the model sees only partially;
   - the conclusions are stable under perturbation (RQ5);
   - detection is checked against independently published attacks (RQ6).
2. **Low-cardinality features.** 98.2% of test feature vectors also appear in training. Splits are grouped by environment, so no environment leaks, and the ambiguity ceiling bounds the achievable accuracy.
3. **Graph coverage.** Credential takeover and code injection are not modelled (the RQ6 misses).
4. **Remediation scope.** A `CAN_ASSUME` patch revokes every AssumeRole statement of the target role, not just the one for the specific principal. The choke-point evaluation assumes any edge can be cut without business impact.
5. **Faithfulness mapping.** The mapping from causes to features was defined by the team; the random baseline shows it isn't trivially satisfied.
6. **Scalability.** Path enumeration is exponential in dense graphs (about 364k paths at 6 hops on a 65-node test graph).

---

## 6. Open Items From the Original Review

| Item | Status |
|---|---|
| Degenerate dataset, circular labels, leakage | ✅ Resolved |
| Dashboard fake SHAP and feature mismatch | ✅ Resolved |
| Deny semantics | ✅ Resolved |
| Dashboard security issues | ✅ Resolved |
| Choke-point matcher bugs | ✅ Resolved |
| Dependency pinning / model compatibility | ✅ Resolved |
| Adjacency index for path search | ✅ Resolved |
| Remediation revokes every trust statement of the role (should target one principal) | ⏳ Open |
| Pruning / streaming in path enumeration for large graphs | ⏳ Open |
| Pre-compiled regexes and indexed resource matching in graph building | ⏳ Open |
| Generic top-level package names (`parser`, `path`), no `pyproject.toml` | ⏳ Open |
| Credential-takeover and code-injection escalation edges | ⏳ Future work (RQ6) |

---

## 7. Reproducing the Results

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt       # Windows; .venv/bin/pip elsewhere
# run everything with the venv interpreter
python -m dataset.main --count 3000 --workers 4 --output data/processed/iam_attack_dataset.csv
python -m models.train
python -m explainability.faithfulness
python -m choke_point.evaluate
python -m experiments.sensitivity
python -m experiments.benchmark
python -m experiments.figures
python -m experiments.summary
python -m pytest -q
```

The whole sequence takes about 25 minutes on a laptop. Every step is seeded, so repeated runs reproduce the same numbers.

### Output inventory (`evaluation/`)

| File | Contents |
|---|---|
| `RESULTS.md` | Consolidated results (RQ1–RQ6, threats, figure list) |
| `model_metrics.json`, `model_report.md` | Phase 6 metrics, CIs, significance, generalisation |
| `explanation_faithfulness.json` | RQ3 |
| `choke_point_evaluation.json` | RQ4 |
| `sensitivity_analysis.json`, `.md` | RQ5 |
| `benchmark_results.json`, `.md` | RQ6, per-technique table |
| `figures/fig1–fig6_*.png` | Publication figures |
| `shap/` | Global SHAP plots and two worked local examples |

---

## 8. Recommended Next Steps

1. **For the presentation:** tag a few resources in `data/scenarios/` with `"DataClassification": "restricted"` so the live dashboard demo shows sensitive-data risk.
2. **For the paper:** use RQ1–RQ6 as the evaluation section and §5 as threats to validity. Present the hybrid model and the RQ2 finding as a contribution.
3. **Next engineering step:** model credential-takeover and code-injection escalation as graph edges, then re-run the benchmark on a fresh set of techniques rather than the same 26.
4. **Remediation precision:** revoke only the trust statement naming the choke point's principal.
