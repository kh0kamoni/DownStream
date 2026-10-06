# DownstreamSec: Predicting Kernel Vulnerability Exposure in Debian and Ubuntu on Day Zero

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dataset: 9,208 CVEs](https://img.shields.io/badge/Dataset-9%2C208%20CVEs-green.svg)](#dataset-schema)
[![Observations: 55,248](https://img.shields.io/badge/Observations-55%2C248-orange.svg)](#dataset-schema)

This repository contains the replication package, empirical datasets, machine learning pipeline, and LaTeX manuscript for the paper:

> **DownstreamSec: Predicting Kernel Vulnerability Exposure in Debian and Ubuntu on Day Zero**

---

## Overview

When a security vulnerability is fixed in the upstream Linux kernel, downstream distributions (e.g., Debian, Ubuntu) do not receive immediate protection. Instead, downstream packages must backport, test, and release patched kernel builds across multiple supported Long-Term Support (LTS) releases. 

**DownstreamSec** investigates this delay across two decades (2005–2024) and demonstrates that downstream exposure can be reliably predicted on **Day Zero** (the moment an upstream fixing commit is pushed, well before public CVE disclosure).

### Key Empirical Findings

- **Multi-Source Empirical Corpus**: 9,208 common Linux kernel CVEs spanning 55,248 release observations across 6 Debian and Ubuntu LTS releases (`bullseye`, `bookworm`, `trixie`, `focal`, `jammy`, `noble`), with 40,198 confirmed remediation events.
- **Protracted Remediation Delay**: The median downstream remediation delay is **258.8 days** (mean: 306.6 days) after upstream commit. Kaplan-Meier survival analysis indicates that **77.6%** of vulnerabilities remain unresolved past 90 days, and **54.7%** remain unresolved past a full year.
- **Day-Zero Information Availability**: In **99.97%** of evaluated CVEs, upstream fixing commits predate public CVE disclosure ($t_{\text{upstream\_commit}} \le t_{\text{disclosure}}$), providing an actionable window for distribution maintainers.
- **Predictive Exposure Modeling**: Trained exclusively on features available on Day Zero (diff size, affected subsystems, upstream stable tags, release lifetime), an XGBoost model predicts downstream exposure on held-out prospective data ($\ge 2024$, $N = 32,536$) with:
  - **ROC-AUC: 0.8114**
  - **PR-AUC: 0.4793**
  - **Balanced Accuracy: 65.24%** (Logistic Regression reaches **75.48%**)
- **Operational Triage**: By prioritizing the top 50% highest-risk CVE-release pairs, distribution security teams can capture **94.3%** of prolonged exposures while reducing review workload by half.

---

## Dataset Schema

All data is constructed from authentic, authoritative sources without synthetic records. The dataset is organized into four relational tables available in both Apache Parquet (`.parquet`) and CSV (`.csv`) formats under [`data/pilot/`](file:///c:/Users/Khoka%20Moni/Downloads/research_all/downstream/data/pilot):

| Table | File | Primary Key | Description | Records |
|-------|------|-------------|-------------|---------|
| **Table A** | `table_a_vulnerability` | `cve_id` | NVD, OSV, and kernel.org metadata: CVSS v2/v3, CWE, attack vector, severity, affected subsystem | 9,208 |
| **Table B** | `table_b_upstream_patch` | `cve_id` | Upstream Git commit details: commit SHA, files changed, additions, deletions, patch diff | 9,208 |
| **Table C** | `table_c_downstream_state` | `cve_id, downstream, downstream_version` | Release-level security state (D0–D6), binary exposure label, fixed package version | 55,248 |
| **Table D** | `table_d_temporal_events` | `cve_id, downstream, event_type` | Multi-timestamp chronology: commit date, CVE disclosure date, downstream release fix date, latency windows | 40,198 |

### Security State Taxonomy

Downstream vulnerability states are standardized into a 7-state taxonomy and collapsed for binary classification:

| Code | State Label | Description | Binary Label |
|:----:|:------------|:------------|:------------:|
| **D0** | `not_affected` | Vulnerable upstream code was never introduced into this release branch | `NOT_EXPOSED` (0) |
| **D1** | `vulnerable` | Vulnerability exists in release kernel and has not been resolved | `EXPOSED` (1) |
| **D2** | `fixed_equivalent` | Upstream fix backported identically or directly adopted | `NOT_EXPOSED` (0) |
| **D3** | `modified_fix` | Patch adapted or refactored for downstream branch | `NOT_EXPOSED` (0) |
| **D4** | `partial_fix` | Incomplete fix or deferred remediation under active exposure | `EXPOSED` (1) |
| **D5** | `config_unreachable` | Code present in tree but disabled in distribution kernel config | `NOT_EXPOSED` (0) |
| **D6** | `uncertain` | Ambiguous state in distribution tracking database | Excluded |

---

## Repository Structure

```
downstream/
├── README.md                      # This file
├── requirements.txt               # Python package dependencies
├── config.yaml                    # Global pipeline configuration
│
├── ficta_paper/                   # Double-blind Springer LNCS manuscript
│   ├── main.tex                   # LaTeX manuscript source (12-page budget)
│   ├── references.bib             # BibTeX reference database
│   ├── llncs.cls                  # Springer LNCS document class
│   ├── main.pdf                   # Compiled submission PDF
│   └── figures/                   # Vector PDF figures for LaTeX inclusion
│
├── figures/                       # Publication vector PDFs and raster PNGs
│   ├── fig1_survival_remediation_latency.pdf
│   ├── fig2_roc_pr_curves.pdf
│   ├── fig3_feature_importance.pdf
│   └── fig4_security_state_taxonomy.pdf
│
├── results/                       # Empirical benchmark outputs and reports
│   ├── rq1_exposure_benchmarks.csv
│   ├── rq1_feature_importance.json
│   ├── rq2_latency_benchmarks.csv
│   ├── rq2_feature_importance.json
│   ├── ablation_experiments.csv
│   └── empirical_evaluation_report.md
│
├── src/                           # Complete Python source code
│   ├── pipeline.py                # 11-step end-to-end data pipeline
│   ├── ingest/                    # Collectors for NVD, kernel.org, OSV, Debian, Ubuntu
│   │   ├── debian_collector.py
│   │   ├── kernel_vulns_collector.py
│   │   ├── nvd_collector.py
│   │   ├── osv_collector.py
│   │   └── ubuntu_collector.py
│   ├── select/                    # CVE filtering and intersection selector
│   │   └── cve_selector.py
│   ├── build/                     # Relational dataset builders
│   │   ├── table_a_vulnerability.py
│   │   ├── table_b_upstream_patch.py
│   │   ├── table_c_downstream_state.py
│   │   └── table_d_temporal_events.py
│   ├── model/                     # Machine learning training and benchmarking
│   │   ├── feature_builder.py
│   │   ├── train_exposure.py
│   │   ├── train_latency.py
│   │   └── run_experiments.py
│   ├── visualize/                 # Publication figure generation
│   │   └── generate_paper_figures.py
│   ├── evaluate/                  # Data coverage validation
│   │   └── coverage_report.py
│   └── utils/                     # Git utilities and data parsers
│       ├── git_utils.py
│       └── parsers.py
│
└── data/
    ├── raw/                       # Cached upstream tracker dumps and git mirrors
    └── pilot/                     # Processed 4-table datasets (Parquet + CSV)
```

---

## Quick Start & Reproduction

### 1. Environment Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/kh0kamoni/DownStream.git
cd DownStream

python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Machine Learning Benchmarks

To train all Day-Zero models (Dummy Baseline, Logistic Regression, Random Forest, LightGBM, and XGBoost) using strict out-of-time temporal splits ($\le 2023$ train, $\ge 2024$ test) and output the benchmark tables:

```bash
python -m src.model.run_experiments
```

This updates:
- `results/rq1_exposure_benchmarks.csv`
- `results/rq1_feature_importance.json`
- `results/empirical_evaluation_report.md`

### 3. Generate Paper Figures

To reproduce the four publication-grade vector PDF and high-resolution PNG figures directly from the parquet tables:

```bash
python -m src.visualize.generate_paper_figures
```

The generated figures will be saved in `figures/`, `paper/figures/`, and `ficta_paper/figures/`:
- `fig1_survival_remediation_latency.pdf` — Empirical CDF and Kaplan-Meier survival curves.
- `fig2_roc_pr_curves.pdf` — ROC and Precision-Recall evaluation curves.
- `fig3_feature_importance.pdf` — Mean Gini feature importances across Day-Zero predictors.
- `fig4_security_state_taxonomy.pdf` — Distribution of vulnerability exposure states across Debian and Ubuntu.

### 4. Build LaTeX Manuscript

The paper is typeset using the official Springer LNCS class and strictly budgeted to 12 pages. To compile the PDF:

```bash
cd ficta_paper
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

The resulting `main.pdf` contains the anonymized double-blind review copy.

---

## Data Sources & Integrity

All ground-truth data is retrieved directly from official distribution infrastructure:

1. **National Vulnerability Database (NVD)**: CVE metadata, CVSS scores, CWE taxonomy via NVD API v2.0.
2. **Linux Kernel Vulns Git**: Authoritative CVE 5.0 records from `kernel.org` tracking upstream fixing commits and affected branches.
3. **Open Source Vulnerabilities (OSV.dev)**: Cross-ecosystem vulnerability mappings.
4. **Debian Security Tracker**: Official Debian package security tracking database (`security-tracker.debian.org`).
5. **Canonical Ubuntu Security Tracker**: Official Ubuntu CVE tracking repository (`git.launchpad.net/ubuntu-cve-tracker`).

**Zero Synthetic Data**: Every single observation in this dataset represents an authenticated CVE record with verified upstream commit SHAs and official distribution package changelog entries.

---

## Citation

```bibtex
@inproceedings{downstreamsec2026,
  title     = {DownstreamSec: Predicting Kernel Vulnerability Exposure in Debian and Ubuntu on Day Zero},
  author    = {Anonymous Author(s)},
  booktitle = {Proceedings of the International Conference on Frontiers of Intelligent Computing: Theory and Applications (FICTA)},
  year      = {2026},
  publisher = {Springer}
}
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
