import json
import logging
import shutil
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
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import make_pipeline
import lightgbm as lgb
import xgboost as xgb

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

KERNEL_VERSION_MAP = {
    'focal': 5.4,
    'jammy': 5.15,
    'noble': 6.8,
    'bookworm': 6.1,
    'sid': 6.8,
    'trixie': 6.12
}

LTS_MAP = {
    'focal': 1,
    'jammy': 1,
    'noble': 1,
    'bookworm': 1,
    'sid': 0,
    'trixie': 0
}

RELEASE_DATES = {
    'focal': '2020-04-23',
    'jammy': '2022-04-21',
    'noble': '2024-04-25',
    'bookworm': '2023-06-10',
    'sid': '2000-01-01',
    'trixie': '2023-06-10'
}

class CleanPaperFigureGenerator:
    """Generates synchronized publication figures for DownstreamSec."""

    def __init__(self, pilot_dir: str = "data/pilot", output_dir: str = "figures", paper_figures_dir: str = "paper/figures"):
        self.pilot_dir = Path(pilot_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.paper_figures_dir = Path(paper_figures_dir)
        self.paper_figures_dir.mkdir(parents=True, exist_ok=True)

    def load_clean_data(self):
        df_a = pd.read_parquet(self.pilot_dir / "table_a_vulnerability.parquet")
        df_b = pd.read_parquet(self.pilot_dir / "table_b_upstream_patch.parquet")
        df_c = pd.read_parquet(self.pilot_dir / "table_c_downstream_state.parquet")

        df = df_c.merge(df_a, on='cve_id', how='left')
        df = df.merge(
            df_b[['cve_id', 'files_changed_count', 'loc_added', 'loc_deleted', 'loc_delta', 'patch_hunks', 'commit_message_length', 'is_single_file_fix']],
            on='cve_id',
            how='left'
        )
        df['downstream_kernel_ver'] = df['downstream_version'].map(KERNEL_VERSION_MAP).fillna(6.0)
        df['is_lts'] = df['downstream_version'].map(LTS_MAP).fillna(0)
        df['cve_year'] = df['cve_id'].apply(lambda x: int(x.split('-')[1]) if '-' in x else 2024)

        # Release validity filtering (zero anachronisms)
        df['rel_start'] = df['downstream_version'].map(RELEASE_DATES)
        df['pub_date'] = df['published_at'].str.slice(0, 10)
        df = df[df['pub_date'] >= df['rel_start']].copy()

        cat_cols = ['downstream', 'attack_vector', 'attack_complexity', 'affected_component', 'vulnerability_type']
        num_cols = ['cvss', 'reference_count', 'files_changed_count', 'loc_added', 'loc_deleted', 'loc_delta', 'patch_hunks', 'commit_message_length', 'downstream_kernel_ver', 'is_lts', 'is_single_file_fix']

        for c in num_cols:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)
        for c in cat_cols:
            df[c] = df[c].fillna('unknown').astype(str)

        train_mask = df['cve_year'] <= 2023
        test_mask = df['cve_year'] >= 2024

        df_train = df[train_mask].copy()
        df_test = df[test_mask].copy()

        encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        train_cat = encoder.fit_transform(df_train[cat_cols])
        test_cat = encoder.transform(df_test[cat_cols])

        feature_names = num_cols + list(encoder.get_feature_names_out(cat_cols))

        X_train = np.hstack([df_train[num_cols].values, train_cat])
        X_test = np.hstack([df_test[num_cols].values, test_cat])

        y_train = (df_train['security_state_binary'] == 'EXPOSED').astype(int).values
        y_test = (df_test['security_state_binary'] == 'EXPOSED').astype(int).values

        return X_train, y_train, X_test, y_test, feature_names

    def generate_fig1(self) -> None:
        """Figure 1: Empirical Remediation Latency & Survival Curves."""
        logging.info("Generating Figure 1: Remediation Latency & Survival Curves...")
        df_d = pd.read_parquet(self.pilot_dir / "table_d_temporal_events.parquet")
        df_down = df_d[df_d['downstream'].isin(['debian', 'ubuntu']) & df_d['remediation_latency_days'].notnull()].copy()

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

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
        for p in [self.output_dir, self.paper_figures_dir]:
            plt.savefig(p / "fig1_survival_remediation_latency.pdf")
            plt.savefig(p / "fig1_survival_remediation_latency.png")
        plt.close()

    def generate_fig2(self) -> None:
        """Figure 2: Model Performance ROC & PR Curves (Synchronized to Table 2)."""
        logging.info("Generating Figure 2: Synchronized ROC & PR Curves...")
        X_train, y_train, X_test, y_test, _ = self.load_clean_data()

        models = {
            "XGBoost": xgb.XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=6, eval_metric='logloss', random_state=42, n_jobs=-1),
            "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)),
            "LightGBM": lgb.LGBMClassifier(n_estimators=150, learning_rate=0.05, class_weight='balanced', random_state=42, verbose=-1),
            "Random Forest": RandomForestClassifier(n_estimators=150, max_depth=12, class_weight='balanced', random_state=42, n_jobs=-1)
        }

        palette = {'XGBoost': '#2ca02c', 'Logistic Regression': '#9467bd', 'LightGBM': '#1f77b4', 'Random Forest': '#d62728'}

        fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(13, 5))

        for name, clf in models.items():
            clf.fit(X_train, y_train)
            probs = clf.predict_proba(X_test)[:, 1]

            fpr, tpr, _ = roc_curve(y_test, probs)
            auc = roc_auc_score(y_test, probs)
            ax_roc.plot(fpr, tpr, label=f'{name} (AUC = {auc:.3f})', color=palette[name], lw=2.2)

            prec, rec, _ = precision_recall_curve(y_test, probs)
            pr_auc = average_precision_score(y_test, probs)
            ax_pr.plot(rec, prec, label=f'{name} (PR-AUC = {pr_auc:.3f})', color=palette[name], lw=2.2)

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
        for p in [self.output_dir, self.paper_figures_dir]:
            plt.savefig(p / "fig2_roc_pr_curves.pdf")
            plt.savefig(p / "fig2_roc_pr_curves.png")
        plt.close()

    def generate_fig3(self) -> None:
        """Figure 3: Top Day-Zero Permutation Feature Importances on Prospective Test Set."""
        logging.info("Generating Figure 3: Day-Zero Permutation Feature Importances...")
        X_train, y_train, X_test, y_test, feature_names = self.load_clean_data()

        clf = xgb.XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=6, eval_metric='logloss', random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)

        from sklearn.inspection import permutation_importance
        perm = permutation_importance(clf, X_test[:5000], y_test[:5000], n_repeats=5, random_state=42, scoring='roc_auc')
        importances = perm.importances_mean

        # Select top 12 positive importances
        sorted_idx = np.argsort(importances)[::-1][:12]

        top_names = [feature_names[i] for i in sorted_idx][::-1]
        top_vals = [max(0.0, float(importances[i])) for i in sorted_idx][::-1]

        max_v = max(top_vals) if top_vals and max(top_vals) > 0 else 1.0
        norm_vals = [v / max_v * 100 for v in top_vals]

        label_map = {
            'commit_message_length': 'Commit Message Length (chars)',
            'patch_hunks': 'Patch Hunk Complexity',
            'files_changed_count': 'Patch Scope (Files Modified)',
            'downstream_kernel_ver': 'Downstream Base Kernel Version',
            'is_lts': 'LTS Maintenance Policy Indicator',
            'cvss': 'CVSS v3.1 Base Score',
            'reference_count': 'Advisory Reference Count',
            'loc_delta': 'Patch Net Code Churn (Delta)',
            'loc_added': 'Patch Code Expansion (LOC Added)',
            'loc_deleted': 'Patch Code Reduction (LOC Deleted)',
            'is_single_file_fix': 'Single-File Surgical Patch',
            'downstream_ubuntu': 'Ecosystem: Ubuntu Pipeline',
            'downstream_debian': 'Ecosystem: Debian Pipeline',
            'affected_component_mm': 'Subsystem: Memory Management (mm)',
            'affected_component_net': 'Subsystem: Networking (net)',
            'affected_component_bluetooth': 'Subsystem: Bluetooth Stack',
            'vulnerability_type_out-of-bounds-read': 'Vulnerability: Out-of-Bounds Read',
            'vulnerability_type_other': 'Vulnerability: Uncategorized CWE'
        }
        clean_labels = [label_map.get(n, n) for n in top_names]

        plt.figure(figsize=(10, 6.2))
        colors = sns.color_palette("Blues_r", len(norm_vals))

        bars = plt.barh(clean_labels, norm_vals, color=colors, edgecolor='gray', height=0.65)
        for bar, val in zip(bars, top_vals):
            w = bar.get_width()
            plt.text(w + 1.2, bar.get_y() + bar.get_height() / 2, f'{w:.1f}% (+{val:.4f} AUC)', ha='left', va='center', fontsize=9.0, fontweight='bold')

        plt.xlim(0, 125)
        plt.xlabel('Relative Permutation Importance (% of Maximum ROC-AUC Drop)')
        plt.title('Prospective Permutation Feature Importance on Held-Out Test Set (Zero Lookahead)')
        plt.tight_layout()
        for p in [self.output_dir, self.paper_figures_dir]:
            plt.savefig(p / "fig3_feature_importance.pdf")
            plt.savefig(p / "fig3_feature_importance.png")
        plt.close()

    def generate_fig4(self) -> None:
        """Figure 4: Security State Taxonomy (D0–D6) Distribution Across Releases."""
        logging.info("Generating Figure 4: Taxonomy Distribution across Releases...")
        df_c = pd.read_parquet(self.pilot_dir / "table_c_downstream_state.parquet")

        ct = pd.crosstab(df_c['downstream_version'], df_c['security_state'], normalize='index') * 100
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
            'D0_not_affected': '#2ca02c',
            'D2_fixed_equivalent': '#1f77b4',
            'D3_modified_fix': '#aec7e8',
            'D1_vulnerable': '#d62728'
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
        for p in [self.output_dir, self.paper_figures_dir]:
            plt.savefig(p / "fig4_security_state_taxonomy.pdf")
            plt.savefig(p / "fig4_security_state_taxonomy.png")
        plt.close()

    def run(self) -> None:
        self.generate_fig1()
        self.generate_fig2()
        self.generate_fig3()
        self.generate_fig4()
        logging.info("All synchronized publication figures generated and copied to figures/ and paper/figures/.")

if __name__ == "__main__":
    gen = CleanPaperFigureGenerator()
    gen.run()
