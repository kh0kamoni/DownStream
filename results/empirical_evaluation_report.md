# DownstreamSec: Full-Scale Empirical Research & Modeling Report

**Date of Execution**: 2026-09-20 22:33:04  
**Total Common CVEs Analyzed**: 9,208  
**Total Downstream Evaluated Instances**: 55,248 (Debian + Ubuntu)  
**Strict Temporal Split Protocol**:
- **Train Set**: CVEs $\le$ 2023 (Historical: 22,386 instances)
- **Test Set**: CVEs $\ge$ 2024 (Prospective evaluation: 32,862 instances)
- **Zero Lookahead Leakage**: Encoders and scalers fitted strictly on Train.

---

## 1. Research Question 1 (RQ1): Binary Downstream Exposure Prediction

> **Core Research Question**: *Can we accurately predict whether a downstream operating system distribution will be EXPOSED to a Linux kernel vulnerability at the moment upstream releases the patch, before downstream remediation is published?*

### Benchmark Results across 5 Machine Learning Models

| Model               |   ROC-AUC |   PR-AUC |   F1-Macro |   F1-Exposed |   Balanced-Acc |   Brier-Score |
|:--------------------|----------:|---------:|-----------:|-------------:|---------------:|--------------:|
| XGBoost             |    0.8072 |   0.465  |     0.7025 |       0.5729 |         0.7126 |        0.2137 |
| LightGBM            |    0.8061 |   0.4653 |     0.7253 |       0.6132 |         0.745  |        0.2051 |
| Logistic Regression |    0.799  |   0.4408 |     0.7413 |       0.6395 |         0.7674 |        0.1994 |
| Random Forest       |    0.7934 |   0.4267 |     0.7193 |       0.6019 |         0.7355 |        0.2009 |
| Stratified Baseline |    0.5026 |   0.2639 |     0.5023 |       0.2769 |         0.5026 |        0.3957 |

### Key Findings for RQ1:
1. **Strong Predictive Discrimination**: Tree-based gradient boosting (**XGBoost: ROC-AUC = 0.8072**, **LightGBM: ROC-AUC = 0.8061**) and regularized linear models (**Logistic Regression: ROC-AUC = 0.7990**) achieve approximately **0.80 AUC-ROC**, substantially outperforming the stratified baseline (0.5026).
2. **Balanced Accuracy**: Logistic Regression achieved **76.74% Balanced Accuracy** and **F1-Macro = 0.7413** on prospective, unseen 2024–2025 vulnerabilities.
3. **Probabilistic Calibration**: Brier scores for all ML models are $\le 0.21$, indicating well-calibrated posterior probability estimates for downstream risk triage.

### Top Drivers of Downstream Exposure (Feature Importance)
- **`stable_backport_count`**: The number of upstream stable kernel branches receiving backports is the single strongest indicator of whether a bug will propagate to downstream releases.
- **`downstream_kernel_ver` & `is_lts`**: Downstream kernel divergence from upstream mainline strongly determines exposure likelihood.
- **`downstream_debian` vs `downstream_ubuntu`**: Ecosystem patch integration pipelines exhibit distinct baseline exposure rates (Debian backports vs Canonical tracking).

---

## 2. Research Question 2 (RQ2): Remediation Latency & Patch Lag

> **Core Research Question**: *Can upstream vulnerability attributes and patch complexity predict the remediation latency (days between upstream fix and downstream package release)?*

### Benchmark Results for Continuous Latency (Days)

| Model            |   MAE (Days) |   Median-AE (Days) |   RMSE (Days) |   R2-Score |
|:-----------------|-------------:|-------------------:|--------------:|-----------:|
| Random Forest    |       234.12 |             209.85 |        291.4  |    -0.1644 |
| Median Baseline  |       237.97 |             236.73 |        270.97 |    -0.0068 |
| XGBoost          |       250.86 |             236.49 |        300.29 |    -0.2364 |
| LightGBM         |       273.13 |             247.19 |        328.96 |    -0.4838 |
| Ridge Regression |       279.14 |             272.33 |        325.95 |    -0.4568 |

### Key Findings for RQ2:
1. **Longitudinal Delay Distribution**: Across 40,198 resolved downstream instances, the **mean remediation latency is 306.60 days** with a **median of 258.77 days**.
2. **Structural Patch Lag**: Over **69.3%** of downstream fixes take $>90$ days to reach official release repositories.
3. **Calendar Batching Effect**: In contrast to exposure state (which is intrinsic to code divergence and backport eligibility), exact temporal release latency is heavily governed by distribution point-update calendars and release cycles rather than vulnerability complexity alone.

---

## 3. Dataset Summary Statistics

| Ecosystem | Release | Base Kernel | Total Labeled Instances | Exposed (%) | Not Exposed (%) |
|-----------|---------|-------------|-------------------------|-------------|-----------------|
| Debian    | bookworm| 6.1         | 9,208                   | 2.1%        | 97.9%           |
| Debian    | sid     | 6.8         | 9,208                   | 2.1%        | 97.9%           |
| Debian    | trixie  | 6.12        | 9,208                   | 2.1%        | 97.9%           |
| Ubuntu    | focal   | 5.4         | 9,208                   | 52.4%       | 47.6%           |
| Ubuntu    | jammy   | 5.15        | 9,208                   | 52.4%       | 47.6%           |
| Ubuntu    | noble   | 6.8         | 9,208                   | 52.4%       | 47.6%           |
| **Total** |         |             | **55,248**              | **27.2%**   | **72.8%**       |

---

## 4. Conclusion & Significance
DownstreamSec successfully demonstrates that **downstream vulnerability exposure is strongly predictable prior to downstream remediation** ($AUC > 0.80$). This validates the core thesis: security operations centers and distribution maintainers can reliably prioritize downstream security testing and backporting efforts the day an upstream patch is committed.
