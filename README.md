# DownstreamSec: Predicting Kernel Vulnerability Exposure in Debian and Ubuntu on Day Zero

Code and datasets for studying and predicting security patch delays between the upstream Linux kernel and downstream distributions (Debian and Ubuntu).

---

## Overview

When a security vulnerability is fixed in the upstream Linux kernel, downstream distributions do not receive immediate protection. Maintainers must backport patches, resolve code conflicts, and compile kernel packages for each supported LTS release.

This project analyzes patch propagation across 20 years (2005–2024) and trains machine learning models to predict downstream exposure on **Day Zero** (the date the upstream fixing commit lands in git, before public CVE disclosure).

### Summary of Results

- **Dataset**: 9,208 common Linux kernel CVEs across 55,248 release observations spanning 6 Debian and Ubuntu LTS releases (`bullseye`, `bookworm`, `trixie`, `focal`, `jammy`, `noble`), with 40,198 confirmed fixes.
- **Patch Latency**: Median delay between upstream commit and downstream package release is **258.8 days** (mean: 306.6 days). Over 77% of vulnerabilities remain unpatched after 90 days.
- **Day-Zero Lead Time**: In **99.97%** of CVEs, the upstream commit occurs before public CVE disclosure (*t*<sub>commit</sub> &le; *t*<sub>disclosure</sub>).
- **Exposure Prediction**: Using features available on day zero (patch diff size, affected subsystems, stable tags, release lifetime), models predict downstream exposure on future releases (years &ge; 2024, *N* = 32,536) with:
  - **ROC-AUC: 0.8114** (XGBoost)
  - **Balanced Accuracy: 75.48%** (Logistic Regression)
- **Triage**: Reviewing the top 50% highest-risk CVEs captures **94.3%** of prolonged exposures, cutting maintainer review queues in half.

---

## Dataset Schema

The processed dataset is available in Apache Parquet (`.parquet`) and CSV (`.csv`) in `data/pilot/`:

| Table | File | Key | Description | Records |
|:---|:---|:---|:---|:---|
| **Table A** | `table_a_vulnerability` | `cve_id` | CVE metadata, CVSS scores, CWE, attack vector, subsystem | 9,208 |
| **Table B** | `table_b_upstream_patch` | `cve_id` | Commit SHA, lines added/deleted, files changed, patch diff | 9,208 |
| **Table C** | `table_c_downstream_state` | `cve_id, downstream, downstream_version` | Release status (D0–D6), binary exposure label, fixed package version | 55,248 |
| **Table D** | `table_d_temporal_events` | `cve_id, downstream, event_type` | Commit date, disclosure date, release fix date, latency windows | 40,198 |

### Security State Taxonomy

| Code | State | Description | Binary Label |
|:----:|:------|:------------|:------------:|
| **D0** | `not_affected` | Vulnerable upstream code not present in release | 0 (Not Exposed) |
| **D1** | `vulnerable` | Affected and no fix applied | 1 (Exposed) |
| **D2** | `fixed_equivalent` | Upstream fix backported | 0 (Not Exposed) |
| **D3** | `modified_fix` | Fix adapted for downstream branch | 0 (Not Exposed) |
| **D4** | `partial_fix` | Incomplete fix or deferred update | 1 (Exposed) |
| **D5** | `config_unreachable` | Code present but disabled in kernel config | 0 (Not Exposed) |
| **D6** | `uncertain` | Undetermined status | Excluded |

---

## Project Structure

```
downstream/
├── README.md                      # Documentation
├── requirements.txt               # Dependencies
├── config.yaml                    # Pipeline configuration
├── data/
│   ├── raw/                       # Cached tracker data and git clones
│   └── pilot/                     # 4-table datasets (Parquet and CSV)
├── figures/                       # Plots and diagrams
├── results/                       # Model benchmark outputs and metrics
└── src/
    ├── ingest/                    # Collectors for NVD, kernel.org, OSV, Debian, Ubuntu
    ├── select/                    # CVE intersection filtering
    ├── build/                     # Dataset builders for Tables A, B, C, D
    ├── model/                     # ML models and benchmark runners
    ├── visualize/                 # Figure generation scripts
    ├── evaluate/                  # Coverage reports
    └── utils/                     # Git helpers and parsers
```

---

## Getting Started

### Installation

```bash
git clone https://github.com/kh0kamoni/DownStream.git
cd DownStream

python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### Running the ML Models

Train the models (Logistic Regression, Random Forest, LightGBM, XGBoost) using the prospective temporal split (&le; 2023 train, &ge; 2024 test):

```bash
python -m src.model.run_experiments
```

Results are saved to `results/rq1_exposure_benchmarks.csv` and `results/rq1_feature_importance.json`.

### Generating Figures

Regenerate paper figures from the parquet data:

```bash
python -m src.visualize.generate_paper_figures
```

Output figures:
- `figures/fig1_survival_remediation_latency.pdf` — Kaplan-Meier survival curves and latency distribution.
- `figures/fig2_roc_pr_curves.pdf` — ROC and Precision-Recall curves.
- `figures/fig3_feature_importance.pdf` — Feature importance rankings.
- `figures/fig4_security_state_taxonomy.pdf` — Security state distribution across releases.

---

## Data Sources

All records come from official distribution trackers and kernel archives:

1. **NVD API v2.0** — CVSS scores, CWE, disclosure dates.
2. **kernel.org vulns.git** — Linux kernel CVE records and upstream fixing commit SHAs.
3. **OSV.dev** — Open source vulnerability database mappings.
4. **Debian Security Tracker** — Package tracking data from `security-tracker.debian.org`.
5. **Ubuntu CVE Tracker** — Package tracking repository from Launchpad.

---

## License

This project is licensed under the MIT License.
