import json
import logging
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, precision_recall_curve, roc_auc_score, average_precision_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
import lightgbm as lgb
import xgboost as xgb

from src.model.feature_builder import FeatureBuilder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set publication style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'sans-serif',
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight'
})

class PaperFigureGenerator:
    """Generates publication-quality figures for top-tier security conferences."""

    def __init__(self, pilot_dir: str = "data/pilot", output_dir: str = "figures"):
        self.pilot_dir = Path(pilot_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.builder = FeatureBuilder(str(self.pilot_dir))

    def generate_fig1_remediation_latency(self) -> None:
        """Figure 1: Empirical Patch Lag & Survival Curves (Debian vs Ubuntu)."""
        logging.info("Generating Figure 1: Remediation Latency & Survival Curves...")
        df_d = pd.read_parquet(self.pilot_dir / "table_d_temporal_events.parquet")
        df_down = df_d[df_d['downstream'].isin(['debian', 'ubuntu']) & df_d['remediation_latency_days'].notnull()].copy()

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

        # (a) Cumulative Distribution Function (ECDF)
        deb_lat = df_down[df_down['downstream'] == 'debian']['remediation_latency_days']
        ub_lat = df_down[df_down['downstream'] == 'ubuntu']['remediation_latency_days']

        deb_sorted = np.sort(deb_lat)
        deb_ecdf = np.arange(1, len(deb_sorted) + 1) / len(deb_sorted)

        ub_sorted = np.sort(ub_lat)
        ub_ecdf = np.arange(1, len(ub_sorted) + 1) / len(ub_sorted)

        ax1.plot(deb_sorted, deb_ecdf * 100, label=f'Debian (n={len(deb_lat):,}, median={deb_lat.median():.0f}d)', color='#1f77b4', lw=2.2)
        ax1.plot(ub_sorted, ub_ecdf * 100, label=f'Ubuntu (n={len(ub_lat):,}, median={ub_lat.median():.0f}d)', color='#e6550d', lw=2.2)

        ax1.axvline(30, color='gray', linestyle=':', alpha=0.7, label='30-day window')
        ax1.axvline(90, color='black', linestyle='--', alpha=0.7, label='90-day window')
        ax1.set_xlim(0, 730)
        ax1.set_ylim(0, 105)
        ax1.set_xlabel('Remediation Latency (Days since Upstream Fix)')
        ax1.set_ylabel('Cumulative Resolved Patches (%)')
        ax1.set_title('(a) Cumulative Patch Remediation ECDF')
        ax1.legend(loc='lower right', frameon=True)

        # (b) Empirical Survival Curve S(t) = P(Latency > t)
        t_range = np.linspace(0, 730, 300)
        deb_surv = [(deb_lat > t).mean() * 100 for t in t_range]
        ub_surv = [(ub_lat > t).mean() * 100 for t in t_range]

        ax2.plot(t_range, deb_surv, label='Debian Exposure Window', color='#1f77b4', lw=2.2)
        ax2.plot(t_range, ub_surv, label='Ubuntu Exposure Window', color='#e6550d', lw=2.2)
        ax2.fill_between(t_range, deb_surv, alpha=0.15, color='#1f77b4')
        ax2.fill_between(t_range, ub_surv, alpha=0.15, color='#e6550d')

        ax2.axhline(50, color='gray', linestyle=':', alpha=0.6, label='50% Exposure Threshold')
        ax2.set_xlim(0, 730)
        ax2.set_ylim(0, 105)
        ax2.set_xlabel('Time Horizon (Days since Upstream Fix)')
        ax2.set_ylabel('Vulnerabilities Remaining Exposed (%)')
        ax2.set_title('(b) Downstream Security Exposure Survival S(t)')
        ax2.legend(loc='upper right', frameon=True)

        plt.tight_layout()
        plt.savefig(self.output_dir / "fig1_survival_remediation_latency.pdf")
        plt.savefig(self.output_dir / "fig1_survival_remediation_latency.png")
        plt.close()
        logging.info("Saved Figure 1 to fig1_survival_remediation_latency.{pdf,png}")

    def generate_fig2_roc_pr_curves(self) -> None:
        """Figure 2: Model Performance ROC & Precision-Recall Curves (Prospective Out-of-Time Test)."""
        logging.info("Generating Figure 2: ROC & PR Performance Curves...")
        df = self.builder.load_merged_data()
        X_train, y_train, _, X_test, y_test, _, _ = self.builder.get_feature_matrix(df)

        models = {
            "XGBoost": xgb.XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=6, eval_metric='logloss', random_state=42, n_jobs=-1),
            "LightGBM": lgb.LGBMClassifier(n_estimators=150, learning_rate=0.05, class_weight='balanced', random_state=42, verbose=-1),
            "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)),
            "Random Forest": RandomForestClassifier(n_estimators=150, max_depth=12, class_weight='balanced', random_state=42, n_jobs=-1)
        }

        palette = {'XGBoost': '#2ca02c', 'LightGBM': '#1f77b4', 'Logistic Regression': '#9467bd', 'Random Forest': '#d62728'}

        fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(13, 5))

        for name, clf in models.items():
            clf.fit(X_train, y_train)
            probs = clf.predict_proba(X_test)[:, 1]

            # ROC
            fpr, tpr, _ = roc_curve(y_test, probs)
            auc = roc_auc_score(y_test, probs)
            ax_roc.plot(fpr, tpr, label=f'{name} (AUC = {auc:.3f})', color=palette[name], lw=2.0)

            # PR
            prec, rec, _ = precision_recall_curve(y_test, probs)
            pr_auc = average_precision_score(y_test, probs)
            ax_pr.plot(rec, prec, label=f'{name} (PR-AUC = {pr_auc:.3f})', color=palette[name], lw=2.0)

        # Baseline curves
        ax_roc.plot([0, 1], [0, 1], 'k--', lw=1.5, alpha=0.7, label='Chance (AUC = 0.500)')
        ax_roc.set_xlim([0.0, 1.0])
        ax_roc.set_ylim([0.0, 1.05])
        ax_roc.set_xlabel('False Positive Rate (1 - Specificity)')
        ax_roc.set_ylabel('True Positive Rate (Sensitivity)')
        ax_roc.set_title('(a) Out-of-Time Receiver Operating Characteristic (ROC)')
        ax_roc.legend(loc="lower right", frameon=True)

        baseline_pr = y_test.mean()
        ax_pr.axhline(baseline_pr, color='k', linestyle='--', lw=1.5, alpha=0.7, label=f'Baseline Rate ({baseline_pr:.1%})')
        ax_pr.set_xlim([0.0, 1.0])
        ax_pr.set_ylim([0.0, 1.05])
        ax_pr.set_xlabel('Recall (Sensitivity)')
        ax_pr.set_ylabel('Precision (Positive Predictive Value)')
        ax_pr.set_title('(b) Out-of-Time Precision-Recall (PR) Curves')
        ax_pr.legend(loc="upper right", frameon=True)

        plt.tight_layout()
        plt.savefig(self.output_dir / "fig2_roc_pr_curves.pdf")
        plt.savefig(self.output_dir / "fig2_roc_pr_curves.png")
        plt.close()
        logging.info("Saved Figure 2 to fig2_roc_pr_curves.{pdf,png}")

    def generate_fig3_feature_importance(self) -> None:
        """Figure 3: Relative Importance of Pre-Remediation Predictors."""
        logging.info("Generating Figure 3: Feature Importance Analysis...")
        feat_path = Path("results/rq1_feature_importance.json")
        if not feat_path.exists():
            return
        
        with open(feat_path, "r", encoding="utf-8") as f:
            feat_data = json.load(f)

        # Use LightGBM feature frequencies
        lgb_feats = feat_data.get("LightGBM", {})
        top_items = list(lgb_feats.items())[:12]
        names = [k for k, _ in top_items][::-1]
        vals = [v for _, v in top_items][::-1]

        # Normalized values
        max_v = max(vals) if vals else 1
        norm_vals = [v / max_v * 100 for v in vals]

        # Clean display names
        label_map = {
            'commit_message_length': 'Commit Message Length (chars)',
            'reference_count': 'Advisory Reference Count',
            'stable_backport_count': 'Upstream Stable Backport Branches',
            'downstream_kernel_ver': 'Downstream Base Kernel Version',
            'cvss': 'CVSS v3.1 Severity Score',
            'loc_delta': 'Patch Code Churn (Added - Deleted)',
            'loc_added': 'Patch Lines Added (LOC)',
            'files_changed_count': 'Files Modified in Fix',
            'patch_hunks': 'Patch Hunk Count',
            'is_single_file_fix': 'Single-File Fix Boolean',
            'is_lts': 'LTS Distribution Indicator',
            'downstream_ubuntu': 'Ecosystem: Ubuntu Pipeline',
            'downstream_debian': 'Ecosystem: Debian Pipeline'
        }
        display_names = [label_map.get(n, n) for n in names]

        plt.figure(figsize=(10, 6))
        colors = sns.color_palette("Blues_r", len(norm_vals))

        bars = plt.barh(display_names, norm_vals, color=colors, edgecolor='gray', height=0.65)
        for bar in bars:
            w = bar.get_width()
            plt.text(w + 1.2, bar.get_y() + bar.get_height() / 2, f'{w:.1f}%', ha='left', va='center', fontsize=9.5, fontweight='bold')

        plt.xlim(0, 115)
        plt.xlabel('Relative Feature Importance Score (%)')
        plt.title('Top Pre-Remediation Predictors of Downstream Vulnerability Exposure')
        plt.tight_layout()
        plt.savefig(self.output_dir / "fig3_feature_importance.pdf")
        plt.savefig(self.output_dir / "fig3_feature_importance.png")
        plt.close()
        logging.info("Saved Figure 3 to fig3_feature_importance.{pdf,png}")

    def generate_fig4_taxonomy_distribution(self) -> None:
        """Figure 4: Security State Taxonomy (D0–D6) Distribution Across Releases."""
        logging.info("Generating Figure 4: Taxonomy Distribution across Releases...")
        df_c = pd.read_parquet(self.pilot_dir / "table_c_downstream_state.parquet")

        ct = pd.crosstab(df_c['downstream_version'], df_c['security_state'], normalize='index') * 100

        # Order releases chronologically by ecosystem
        release_order = ['focal', 'jammy', 'noble', 'bookworm', 'sid', 'trixie']
        existing_order = [r for r in release_order if r in ct.index]
        ct = ct.loc[existing_order]

        display_labels = {
            'focal': 'Ubuntu 20.04 LTS (5.4)',
            'jammy': 'Ubuntu 22.04 LTS (5.15)',
            'noble': 'Ubuntu 24.04 LTS (6.8)',
            'bookworm': 'Debian 12 Bookworm (6.1)',
            'sid': 'Debian Sid Unstable (6.8)',
            'trixie': 'Debian 13 Trixie (6.12)'
        }
        ct.index = [display_labels.get(i, i) for i in ct.index]

        state_colors = {
            'D0_not_affected': '#2ca02c',      # Green
            'D2_fixed_equivalent': '#1f77b4',  # Blue
            'D3_modified_fix': '#aec7e8',      # Light blue
            'D1_vulnerable': '#d62728',        # Red
            'D4_partial_fix': '#ff7f0e',       # Orange
            'D5_config_unreachable': '#8c564b',
            'D6_uncertain': '#7f7f7f'
        }

        fig, ax = plt.subplots(figsize=(11, 5.5))
        left = np.zeros(len(ct))

        for col in ['D0_not_affected', 'D2_fixed_equivalent', 'D3_modified_fix', 'D1_vulnerable']:
            if col in ct.columns:
                values = ct[col].values
                color = state_colors.get(col, '#333333')
                label = col.replace('_', ' ').title()
                ax.barh(ct.index, values, left=left, color=color, label=label, edgecolor='white', height=0.6)
                left += values

        ax.set_xlim(0, 100)
        ax.set_xlabel('Proportion of Evaluated Kernel Vulnerabilities (%)')
        ax.set_title('Downstream Security State (D0–D6 Taxonomy) across Target Releases')
        ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.22), ncol=4, frameon=True)

        plt.tight_layout()
        plt.savefig(self.output_dir / "fig4_security_state_taxonomy.pdf")
        plt.savefig(self.output_dir / "fig4_security_state_taxonomy.png")
        plt.close()
        logging.info("Saved Figure 4 to fig4_security_state_taxonomy.{pdf,png}")

    def run(self) -> None:
        self.generate_fig1_remediation_latency()
        self.generate_fig2_roc_pr_curves()
        self.generate_fig3_feature_importance()
        self.generate_fig4_taxonomy_distribution()
        logging.info("All 4 paper figures generated successfully.")

if __name__ == "__main__":
    generator = PaperFigureGenerator()
    generator.run()
