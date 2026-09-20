import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.dummy import DummyRegressor
from sklearn.linear_model import Ridge
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import (
    mean_absolute_error, median_absolute_error, mean_squared_error, r2_score
)
import lightgbm as lgb
import xgboost as xgb

from src.model.feature_builder import FeatureBuilder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LatencyModelTrainer:
    """Trains and benchmarks predictive models for RQ2: Downstream Remediation Latency (Days)."""

    def __init__(self, pilot_dir: str, results_dir: str):
        self.pilot_dir = Path(pilot_dir)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.builder = FeatureBuilder(str(self.pilot_dir))

    def run(self) -> pd.DataFrame:
        df = self.builder.load_merged_data()
        X_train_raw, _, y_train_lat_raw, X_test_raw, _, y_test_lat_raw, feature_names = self.builder.get_feature_matrix(df)

        # Filter to records where remediation latency is observed/computable
        train_valid_idx = ~np.isnan(y_train_lat_raw)
        test_valid_idx = ~np.isnan(y_test_lat_raw)

        X_train = X_train_raw[train_valid_idx]
        y_train = y_train_lat_raw[train_valid_idx]

        X_test = X_test_raw[test_valid_idx]
        y_test = y_test_lat_raw[test_valid_idx]

        logging.info(f"Latency Training Samples: {len(X_train)} (Mean={y_train.mean():.1f}d, Median={np.median(y_train):.1f}d)")
        logging.info(f"Latency Testing Samples:  {len(X_test)} (Mean={y_test.mean():.1f}d, Median={np.median(y_test):.1f}d)")

        models = {
            "Median Baseline": DummyRegressor(strategy="median"),
            "Ridge Regression": make_pipeline(StandardScaler(), Ridge(alpha=1.0, random_state=42)),
            "Random Forest": RandomForestRegressor(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
            "LightGBM": lgb.LGBMRegressor(n_estimators=150, learning_rate=0.05, random_state=42, verbose=-1),
            "XGBoost": xgb.XGBRegressor(n_estimators=150, learning_rate=0.05, max_depth=6, random_state=42, n_jobs=-1)
        }

        results = []
        feature_importance_dict = {}

        for name, reg in models.items():
            logging.info(f"Training {name}...")
            reg.fit(X_train, y_train)

            preds = reg.predict(X_test)
            # Clip predictions to non-negative latency
            preds = np.clip(preds, 0.0, None)

            mae = mean_absolute_error(y_test, preds)
            medae = median_absolute_error(y_test, preds)
            rmse = np.sqrt(mean_squared_error(y_test, preds))
            r2 = r2_score(y_test, preds)

            results.append({
                "Model": name,
                "MAE (Days)": round(mae, 2),
                "Median-AE (Days)": round(medae, 2),
                "RMSE (Days)": round(rmse, 2),
                "R2-Score": round(r2, 4)
            })

            # Feature importance extraction
            estimator = reg.named_steps['ridge'] if hasattr(reg, 'named_steps') else reg
            if hasattr(estimator, "feature_importances_"):
                importances = estimator.feature_importances_
                feature_importance_dict[name] = dict(sorted(
                    zip(feature_names, [round(float(v), 4) for v in importances]),
                    key=lambda x: x[1],
                    reverse=True
                )[:15])
            elif hasattr(estimator, "coef_"):
                importances = np.abs(estimator.coef_)
                feature_importance_dict[name] = dict(sorted(
                    zip(feature_names, [round(float(v), 4) for v in importances]),
                    key=lambda x: x[1],
                    reverse=True
                )[:15])

            logging.info(f"[{name}] MAE: {mae:.2f} days | MedAE: {medae:.2f} days | R2: {r2:.4f}")

        results_df = pd.DataFrame(results).sort_values(by="MAE (Days)", ascending=True)

        metrics_csv = self.results_dir / "rq2_latency_benchmarks.csv"
        results_df.to_csv(metrics_csv, index=False)

        feat_json = self.results_dir / "rq2_feature_importance.json"
        with open(feat_json, "w", encoding="utf-8") as f:
            json.dump(feature_importance_dict, f, indent=2)

        logging.info(f"Saved RQ2 results to {metrics_csv} and {feat_json}")
        return results_df

if __name__ == "__main__":
    trainer = LatencyModelTrainer("data/pilot", "results")
    results = trainer.run()
    print("\n=== RQ2: REMEDIATION LATENCY PREDICTION BENCHMARK RESULTS ===")
    print(results.to_string(index=False))
