import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Any, List
from sklearn.preprocessing import OneHotEncoder, StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

class FeatureBuilder:
    """Constructs leakage-free pre-remediation feature matrices with strict temporal splitting."""

    def __init__(self, pilot_dir: str):
        self.pilot_dir = Path(pilot_dir)
        self.encoder = None
        self.scaler = None
        self.feature_names = []

    def load_merged_data(self) -> pd.DataFrame:
        df_a = pd.read_parquet(self.pilot_dir / "table_a_vulnerability.parquet")
        df_b = pd.read_parquet(self.pilot_dir / "table_b_upstream_patch.parquet")
        df_c = pd.read_parquet(self.pilot_dir / "table_c_downstream_state.parquet")
        df_d = pd.read_parquet(self.pilot_dir / "table_d_temporal_events.parquet")

        # Extract remediation latency from Table D for downstream fix/resolution events
        df_d_downstream = df_d[df_d['downstream'].isin(['debian', 'ubuntu']) & df_d['remediation_latency_days'].notnull()]
        lat_map = df_d_downstream.groupby(['cve_id', 'downstream', 'downstream_version'])['remediation_latency_days'].min().to_dict()

        # Merge Table C (downstream instance) with Tables A and B
        df = df_c.merge(df_a, on='cve_id', how='left')
        df = df.merge(
            df_b[[
                'cve_id', 'files_changed_count', 'loc_added', 'loc_deleted',
                'loc_delta', 'patch_hunks', 'commit_message_length',
                'is_single_file_fix', 'stable_backport_count'
            ]],
            on='cve_id',
            how='left'
        )

        # Attach downstream kernel base version and LTS flag
        df['downstream_kernel_ver'] = df['downstream_version'].map(KERNEL_VERSION_MAP).fillna(6.0)
        df['is_lts'] = df['downstream_version'].map(LTS_MAP).fillna(0)

        # Attach latency target
        df['remediation_latency'] = df.apply(
            lambda r: lat_map.get((r['cve_id'], r['downstream'], r['downstream_version']), np.nan),
            axis=1
        )

        # Extract CVE year for strict temporal splitting
        df['cve_year'] = df['cve_id'].apply(lambda x: int(x.split('-')[1]) if '-' in x else 2024)

        logging.info(f"Loaded and merged {len(df)} total downstream observations across {df['cve_id'].nunique()} unique CVEs.")
        return df

    def get_feature_matrix(
        self,
        df: pd.DataFrame,
        fit_on_train: bool = True
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Produce train and test matrices under strict temporal split:
        Train: CVEs <= 2023 (Historical)
        Test:  CVEs >= 2024 (Prospective)
        """
        # Categorical columns to one-hot encode
        cat_cols = [
            'downstream', 'downstream_version', 'attack_vector',
            'attack_complexity', 'affected_component', 'vulnerability_type'
        ]

        # Numeric features
        num_cols = [
            'cvss', 'reference_count', 'files_changed_count',
            'loc_added', 'loc_deleted', 'loc_delta', 'patch_hunks',
            'commit_message_length', 'stable_backport_count',
            'downstream_kernel_ver', 'is_lts', 'is_single_file_fix'
        ]

        # Ensure types
        for c in num_cols:
            df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0.0)

        for c in cat_cols:
            df[c] = df[c].fillna('unknown').astype(str)

        train_mask = df['cve_year'] <= 2023
        test_mask = df['cve_year'] >= 2024

        df_train = df[train_mask].copy()
        df_test = df[test_mask].copy()

        logging.info(f"Temporal Split: Train (<=2023): {len(df_train)} samples, Test (>=2024): {len(df_test)} samples.")

        # One-hot encoding fitted ONLY on train set to prevent data leakage
        self.encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        train_cat = self.encoder.fit_transform(df_train[cat_cols])
        test_cat = self.encoder.transform(df_test[cat_cols])

        cat_feature_names = list(self.encoder.get_feature_names_out(cat_cols))
        all_feature_names = num_cols + cat_feature_names
        self.feature_names = all_feature_names

        # Combine numeric and categorical
        X_train = np.hstack([df_train[num_cols].values, train_cat])
        X_test = np.hstack([df_test[num_cols].values, test_cat])

        # RQ1 Target: Binary Exposure (1 = EXPOSED, 0 = NOT_EXPOSED)
        y_train_exp = (df_train['security_state_binary'] == 'EXPOSED').astype(int).values
        y_test_exp = (df_test['security_state_binary'] == 'EXPOSED').astype(int).values

        # RQ2 Target: Remediation Latency (Days)
        y_train_lat = df_train['remediation_latency'].values
        y_test_lat = df_test['remediation_latency'].values

        return X_train, y_train_exp, y_train_lat, X_test, y_test_exp, y_test_lat, all_feature_names

if __name__ == "__main__":
    builder = FeatureBuilder("data/pilot")
    df = builder.load_merged_data()
    X_tr, y_tr_e, y_tr_l, X_te, y_te_e, y_te_l, feats = builder.get_feature_matrix(df)
    print(f"X_train: {X_tr.shape}, y_train_exp: {y_tr_e.shape}")
    print(f"X_test:  {X_te.shape}, y_test_exp:  {y_te_e.shape}")
    print(f"Total features: {len(feats)}")
    print(f"Sample features: {feats[:10]}")
