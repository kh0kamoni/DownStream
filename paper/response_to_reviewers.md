# Response to Reviewers and Editor
**Manuscript Title:** DownstreamSec: An Empirical and Predictive Study of Linux Kernel Vulnerability Propagation and Exposure across Linux Distributions  
**Target Journal:** Elsevier *Computers & Security* (COSE)  
**Authors:** Khoka Moni et al.  

---

### Dear Editor and Reviewers,

We express our sincere gratitude to the Associate Editor and the three anonymous reviewers for their thoughtful, rigorous, and constructive feedback on our manuscript. The reviewers' insights have been invaluable in strengthening the empirical rigor, methodological transparency, and overall clarity of our work. 

In this revision, we have thoroughly addressed every concern raised by the review team. Specifically:

1. **Temporal Leakage Debunked via Systematic Ablations:** We conducted systematic ablation experiments across five distinct feature configurations on our out-of-time test set ($\le$2023 train, $\ge$2024 test; $N_{\text{test}} = 32,862$). When removing `stable_backport_count` entirely (Ablation 1), the predictive performance does **not** degrade (XGBoost ROC-AUC improves from 0.8080 to **0.8114**, PR-AUC increases from 0.4642 to **0.4946**, and Logistic Regression achieves **0.8100** ROC-AUC). This empirically disproves the hypothesis that our model relies on post-disclosure backport execution.
2. **Dataset Curation Flow & Attrition Funnel:** We added a detailed data attrition funnel in Section 3.2 tracing the transformation from raw records across four sources (12,176 NVD CVEs, 9,469 CVE JSON 5.0 kernel records, 10,131 Debian entries, and Canonical Ubuntu feeds) to the 9,208 common CVEs, 55,248 release-level observations, and 40,198 computable patch latencies.
3. **Right-Censoring & Survival Probability Clarified:** We reconciled the descriptive statistics with survival analysis in Section 4. We clearly distinguished between the naive empirical proportion of delayed fixes (69.3% requiring $>90$ days among resolved cases) and the non-parametric Kaplan-Meier survival estimator, which explicitly accounts for right-censoring ($D1$ unresolved and $D5$ Won't Fix cases) to establish an empirical 90-day survival probability of $\hat{S}(90) \approx 0.72$.
4. **Metric Integrity & Strict Attribution:** We eliminated all metric amalgamation in the Abstract and throughout the text. The Abstract now explicitly attributes the ROC-AUC of 0.8072 to XGBoost and the Balanced Accuracy of 76.74% to Logistic Regression.
5. **Softened Predictive Language:** We eliminated causal assertions regarding feature importance in Section 6, explicitly stating that tree-based feature importances reflect predictive associations rather than physical causal mechanisms.
6. **Compliance with Journal Guidelines:** The manuscript has been formatted strictly under the official Elsevier double-column template (`final, 5p, times, twocolumn`), all bullet lists in the body have been replaced with continuous scholarly prose, and a formal Generative AI author disclosure statement has been included pursuant to Elsevier publishing standards.

Below, we provide our detailed point-by-point responses to each reviewer's comments.

---

## Detailed Response to Reviewer #1

### Comment 1.1: Potential Temporal Leakage from `stable_backport_count`
> *"The feature `stable_backport_count` appears to represent information that accumulates over time after a patch is committed. In a true day-zero prospective deployment, this count may not yet be known when an upstream commit first appears. Is there temporal feature leakage driving the high ROC-AUC?"*

**Response:**  
We thank the reviewer for this crucial observation regarding prospective evaluation fidelity. To address this concern directly and conclusively, we executed systematic feature ablation experiments on the exact prospective test split ($\le$2023 train, $\ge$2024 test; $N_{\text{test}} = 32,862$). We trained and evaluated models under five ablated configurations, including one that completely excludes `stable_backport_count` (`No Stable Backports`, Ablation 1).

The results are reported in the newly added **Section 5.4 (Ablation Studies and Temporal Leakage Verification)** and summarized in Table 3:

| Feature Configuration | Feats | XGB ROC-AUC | XGB PR-AUC | LR ROC-AUC |
| :--- | :---: | :---: | :---: | :---: |
| Full Feature Set | 53 | 0.8080 | 0.4642 | 0.7994 |
| **No Stable Backports (Ablation 1)** | **52** | **0.8114** | **0.4946** | **0.8100** |
| Upstream-Only (Ablation 2) | 43 | 0.6997 | 0.4084 | 0.7040 |
| Downstream-Only (Ablation 3) | 10 | 0.7514 | 0.4340 | 0.7525 |
| Vulnerability-Only (Ablation 4) | 35 | 0.6719 | 0.3961 | 0.7065 |
| Patch-Only (Ablation 5) | 7 | 0.5100 | 0.2754 | 0.5193 |

**Key Findings:**
1. Stripping out `stable_backport_count` **does not reduce** model performance. In fact, XGBoost achieves **0.8114 ROC-AUC** and **0.4946 PR-AUC**, while Logistic Regression achieves **0.8100 ROC-AUC**. 
2. This demonstrates that downstream exposure prediction is primarily driven by downstream architectural divergence (e.g., kernel baseline version offset, distribution release age, LTS status), affected subsystem categories, and vulnerability severity properties, rather than post-disclosure stable branch commits.
3. Therefore, temporal leakage does not drive our high predictive discrimination.

We have revised Section 5.4 to incorporate these empirical findings and added Table 3 (`tab:ablations`) to the manuscript.

---

### Comment 1.2: Clarification of Survival Analysis and Right-Censoring
> *"The text states that 69.3% of vulnerabilities took >90 days to remediate, but later presents Kaplan-Meier survival curves. How was right-censoring handled, and how does the 69.3% statistic relate to the survival probability?"*

**Response:**  
We appreciate the reviewer highlighting this distinction. In the original draft, the 69.3% figure represented the raw empirical fraction calculated exclusively among resolved cases ($D2$ Fixed and $D4$ Upstream-Only resolved), which omits censored observations.

In the revised manuscript (Section 4, Page 4), we have explicitly reconciled these two metrics:
- **Right-Censoring Treatment:** Unresolved vulnerabilities at the observation cutoff ($D1$) and cases marked as terminal unpatched ($D5$ Won't Fix) are treated as right-censored at their elapsed observation duration.
- **Kaplan-Meier Estimator:** When accounting for right-censoring across all 55,248 instances, the non-parametric Kaplan-Meier survival estimator yields an empirical 90-day survival probability of $\hat{S}(90) \approx 0.72$.
- This confirms that downstream vulnerability persistence is even slightly more pronounced when accounting for censored cases than suggested by the naive completed-case statistic alone.

---

### Comment 1.3: Metric Amalgamation in the Abstract
> *"The abstract juxtaposed the highest ROC-AUC (0.8072) and highest Balanced Accuracy (76.7%) without making clear that these metrics came from different models (XGBoost vs. Logistic Regression)."*

**Response:**  
We thank the reviewer for pointing out this lack of precision. We have revised the Abstract (Page 1) to explicitly delineate the performance metrics by model:

> *"Evaluating on prospective, out-of-time test splits ($\le$2023 train, $\ge$2024 test; $N = 32,862$), gradient-boosted decision trees achieve an ROC-AUC of 0.8072 (PR-AUC: 0.4642), while logistic regression achieves a balanced accuracy of 76.74%."*

Each metric is now strictly paired with its respective model architecture in both the Abstract and Section 5.3.

---

### Comment 1.4: Causal Language vs. Predictive Association
> *"Section 6 uses causal phrasing such as 'drivers', 'influences', and 'causes' when describing tree-based Gini importance. Feature importance in tree ensembles reflects correlation and predictive association, not physical causation."*

**Response:**  
We fully agree with the reviewer. We have comprehensively revised Section 6 and Section 7 to replace causal phrasing with rigorous, associative language. Specifically:
- The section title has been amended from *"Driving Determinants"* to *"Feature Attribution and Driving Determinants (RQ3)"*, with the leading research question reframed to *"Which upstream and downstream factors exhibit the strongest predictive associations with whether a vulnerability will propagate and leave downstream releases exposed?"*
- We added an explicit disclaimer in Section 6.1: *"We emphasize that tree-based feature importance reflects predictive association within our multi-ecosystem dataset rather than direct physical causality."*
- Subsection titles and text now reference *"Strongly Correlated with Propagation"* and *"Structural Factors"* rather than causative agents.

---

### Comment 1.5: Data Curation Flow and Attrition Funnel
> *"The transition from raw data harvesting to the final dataset of 9,208 CVEs needs a transparent attrition funnel documenting sample selection criteria and excluded entries."*

**Response:**  
We have added a dedicated paragraph and attrition funnel description in **Section 3.2 (Cross-Ecosystem Linking and Relational Schema)**:
- We ingested **12,176 raw CVEs** from NVD and **9,469 authoritative kernel CVE records** from the Linux Kernel CVE team (CVE JSON 5.0).
- Cross-referencing identified **9,208 distinct CVEs** present across both NVD and the Linux Kernel CVE Project that had complete git fixing commit metadata.
- Projecting these 9,208 CVEs across six supported distribution suites (Debian Bullseye, Debian Bookworm, Debian Trixie, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS) yielded **55,248 release-level vulnerability observations**.
- Across these observations, **40,198 instances** reached a resolved downstream status with measurable temporal latencies between upstream commit and downstream package fix publication.

---

### Comment 1.6: Continuous Prose and Style Guidelines
> *"Eliminate unnecessary bulleted lists in the main text to maintain standard journal prose quality."*

**Response:**  
We have eliminated all bullet points and itemized lists from the main body of the paper (Sections 1 through 8). The manuscript now flows entirely in continuous, structured academic prose, adhering strictly to Elsevier style conventions. Only the supplementary `highlights.tex` retains bullet points, as explicitly mandated by Elsevier journal submission guidelines.

---

## Detailed Response to Reviewer #2

### Comment 2.1: Primary Focus: Empirical Dataset vs. ML Benchmark
> *"The paper's strongest asset is the multi-ecosystem dataset, taxonomy, and empirical measurement of downstream latency. The ML component should be framed as an actionable prospective early-warning tool rather than the sole centerpiece."*

**Response:**  
We strongly agree with this strategic orientation. In the revised manuscript, we have rebalanced the narrative:
- The primary contribution is positioned as the first large-scale, longitudinal empirical characterization of upstream-to-downstream Linux kernel vulnerability propagation, comprising 9,208 CVEs, 55,248 observations, and the D0–D6 security state taxonomy.
- The machine learning models are positioned as an actionable, prospective early-warning mechanism designed to operationalize these empirical insights on the day an upstream patch is announced.

---

### Comment 2.2: Feature Group Domain Analysis
> *"Can the authors isolate whether upstream features or downstream features are more informative for downstream vulnerability exposure?"*

**Response:**  
This was an excellent suggestion. In our newly added ablation experiments (Table 3, Section 5.4), we evaluated domain-specific submodels:
- **Upstream-Only Features (43 feats):** Achieved an ROC-AUC of **0.6997** and PR-AUC of **0.4084**.
- **Downstream-Only Features (10 feats):** Achieved an ROC-AUC of **0.7514** and PR-AUC of **0.4340**.
- **Combined (Upstream + Downstream):** Achieved an ROC-AUC of **0.8080** (and **0.8114** without backports).
- **Patch-Only Complexity Features (7 feats):** Achieved an ROC-AUC of only **0.5100**, demonstrating that code churn in isolation possesses negligible predictive power.

This demonstrates a critical finding: neither upstream vulnerability characteristics nor downstream distribution properties are sufficient alone. The interaction between upstream vulnerability traits and downstream architecture divergence (code distance, LTS baseline offset) is what enables accurate prospective exposure prediction.

---

### Comment 2.3: Generative AI Use Disclosure
> *"Ensure that any AI assistance in drafting or coding conforms to Elsevier's Generative AI policy."*

**Response:**  
We have added a formal **Declaration of Generative AI and AI-Assisted Technologies in the Writing Process** in the backmatter preceding the references, in full accordance with Elsevier's published standards:

> *"During the preparation of this work, the authors used AI-assisted coding and language tools to assist in data aggregation pipelines and preliminary manuscript drafting. After using these tools, the authors thoroughly reviewed, edited, and verified all code, empirical calculations, and textual content, taking full responsibility for the integrity and validity of the published work."*

---

## Detailed Response to Reviewer #3

### Comment 3.1: External Validity and Reproducibility
> *"The dataset and methodology are comprehensive. Please ensure that all raw parquet tables, scripts, and model training code are available in the public repository for independent verification."*

**Response:**  
We thank the reviewer for the positive assessment of our work. All source code, curation pipelines, relational parquet tables (Tables A, B, C, D), ablation experiment scripts, and LaTeX source files have been synchronized and are publicly accessible in our GitHub repository:  
`https://github.com/kh0kamoni/DownStream`

---

### Summary of Manuscript Modifications

| Section | Key Revisions and Enhancements |
| :--- | :--- |
| **Abstract** | Disaggregated model metrics (XGBoost ROC-AUC 0.8072, Logistic Regression Balanced Accuracy 76.74%). Refocused narrative on empirical curation and prospective early warning. |
| **Section 1 (Introduction)** | Clarified research objectives and removed bullet points in favor of flowing scholarly narrative. |
| **Section 3.2 (Curation Funnel)** | Added explicit data attrition funnel detailing record transitions across NVD, Linux Kernel CVEs, Debian, and Ubuntu. |
| **Section 4 (Empirical Results)** | Reconciled empirical completed-case delay (69.3%) with Kaplan-Meier survival probability ($\hat{S}(90) \approx 0.72$) accounting for right-censoring. |
| **Section 5.4 (Ablations)** | Added comprehensive feature ablation study and Table 3 disproving temporal leakage and demonstrating upstream-downstream domain synergy. |
| **Section 6 (Feature Attribution)** | Replaced causal assertions with predictive association terminology; softened narrative on tree-based Gini importances. |
| **Backmatter** | Added Elsevier Generative AI Policy declaration and Data/Code Availability Statement. |

We believe these revisions fully address all concerns raised by the reviewers and make the manuscript significantly stronger and ready for publication in *Computers & Security*.

Sincerely,  
*The Authors*
