# Sensitivity Analysis

Each variant regenerates the dataset with a different oracle and retrains (scenario-grouped split).

| Variant | Ceiling | LR macro F1 | RF macro F1 | Hybrid macro F1 | Rules macro F1 | RF severe-miss | Hybrid severe-miss |
|---|---:|---:|---:|---:|---:|---:|---:|
| default | 0.890 | 0.755 | 0.875 | 0.875 | 0.378 | 9.1% | 9.1% |
| label_noise_5pct | 0.848 | 0.730 | 0.834 | 0.834 | 0.370 | 10.9% | 10.9% |
| label_noise_10pct | 0.807 | 0.705 | 0.788 | 0.788 | 0.366 | 12.5% | 12.5% |
| weights_perturbed_a | 0.897 | 0.775 | 0.886 | 0.886 | 0.378 | 7.2% | 7.2% |
| weights_perturbed_b | 0.912 | 0.796 | 0.918 | 0.918 | 0.448 | 10.1% | 10.1% |
| weights_perturbed_c | 0.888 | 0.747 | 0.871 | 0.871 | 0.389 | 8.6% | 8.6% |
| thresholds_minus_10pct | 0.878 | 0.770 | 0.863 | 0.863 | 0.388 | 10.0% | 10.0% |
| thresholds_plus_10pct | 0.920 | 0.769 | 0.905 | 0.905 | 0.453 | 9.4% | 9.4% |
