# DownstreamSec

**Predicting Vulnerability Exposure Across Upstream–Downstream Software Ecosystems**

A longitudinal dataset and machine learning framework for security patch propagation analysis.

## Research Unit

The fundamental unit of analysis is:

```
(CVE, upstream_version, downstream_ecosystem, downstream_version)
```

Each record captures whether a specific downstream release is **exposed** to a known upstream vulnerability, based on patch propagation state, source divergence, and configuration differences.

## Project Structure

```
downstream/
├── config.yaml              # Central configuration
├── src/
│   ├── pipeline.py          # Main orchestration (11-step pipeline)
│   ├── ingest/              # Data collection from 5 sources
│   │   ├── nvd_collector.py
│   │   ├── kernel_vulns_collector.py
│   │   ├── osv_collector.py
│   │   ├── debian_collector.py
│   │   └── ubuntu_collector.py
│   ├── select/
│   │   └── cve_selector.py  # 100-CVE pilot selection
│   ├── build/               # 4-table dataset construction
│   │   ├── table_a_vulnerability.py
│   │   ├── table_b_upstream_patch.py
│   │   ├── table_c_downstream_state.py
│   │   └── table_d_temporal_events.py
│   ├── evaluate/
│   │   └── coverage_report.py
│   └── utils/
│       ├── git_utils.py
│       └── parsers.py
└── data/
    ├── raw/                  # Collector outputs
    ├── repos/                # Cloned git repos (gitignored)
    └── pilot/                # Final 4-table dataset
```

## Dataset Schema

| Table | Description | Key |
|-------|-------------|-----|
| **A — Vulnerability** | CVE metadata, CWE, CVSS, attack vector | `cve_id` |
| **B — Upstream Patch** | Fixing commit details, diff stats, patch text | `cve_id` |
| **C — Downstream State** | Per-(CVE, ecosystem, release) security state | `cve_id, downstream, downstream_version` |
| **D — Temporal Events** | Timeline reconstruction per propagation path | `cve_id, downstream, event_type` |

## Security State Taxonomy

| Code | Label | Description |
|------|-------|-------------|
| D0 | not_affected | Vulnerable code absent from downstream |
| D1 | vulnerable | Exposed, no fix applied |
| D2 | fixed_equivalent | Upstream fix applied identically |
| D3 | modified_fix | Fix applied with modifications |
| D4 | partial_fix | Incomplete or deferred fix |
| D5 | config_unreachable | Vulnerable code present but not reachable |
| D6 | uncertain | Insufficient information |

Collapsed: `EXPOSED = {D1, D4}`, `NOT_EXPOSED = {D0, D2, D3, D5}`, `UNCERTAIN = {D6}`

## Data Sources

All data is sourced from real, public infrastructure — **no synthetic data**:

- **NVD API v2.0** — CVE metadata, CVSS, CWE, CPE version ranges
- **kernel.org vulns.git** — Authoritative CVE JSON 5.0 records with fixing/introducing commit SHAs
- **OSV.dev** — Cross-validation bulk export
- **Debian Security Tracker** — Per-release vulnerability status (JSON endpoint + Git repo)
- **Ubuntu CVE Tracker** — Per-release vulnerability status (REST API + Git repo)

## Quick Start

```bash
pip install -r requirements.txt
python -m src.pipeline --config config.yaml
```

## Phase 1: 100-CVE Pilot

Goal: Validate ≥80% automatic coverage across 100 Linux kernel CVEs × Debian × Ubuntu.

Pass criteria:
- ≥80 CVEs fully resolved across all ecosystems
- ≥500 labeled (CVE × downstream_version) records
- ≥90% label accuracy (manual 20-sample check)
- ≥70% records with computable remediation latency
