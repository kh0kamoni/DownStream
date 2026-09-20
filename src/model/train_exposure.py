import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    balanced_accuracy_score, brier_score_loss, classification_report
)
import lightgbm as lgb
import xgboost as xgb

from src.model.feature_builder import FeatureBuilder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ExposureModelTrainer:
    """Trains and benchmarks predictive models for RQ1: Binary Downstream Exposure."""

    def __init__(self, pilot_dir: str, results_dir: str):
        self.pilot_dir = Path(pilot_dir)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.builder = FeatureBuilder(str(self.pilot_dir))

    def run(self) -> pd.DataFrame:
        df = self.builder.load_merged_data()
        X_train, y_train, _, X_test, y_test, _, feature_names = self.builder.get_feature_matrix(df)

        logging.info(f"Target distribution (Train): Positive={y_train.sum()}/{len(y_train)} ({y_train.mean():.1%})")
        logging.info(f"Target distribution (Test):  Positive={y_test.sum()}/{len(y_test)} ({y_test.mean():.1%})")

        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import make_pipeline

        models = {
            "Stratified Baseline": DummyClassifier(strategy="stratified", random_state=42),
            "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)),
            "Random Forest": RandomForestClassifier(n_estimators=150, max_depth=12, class_weight='balanced', random_state=42, n_jobs=-1),
            "LightGBM": lgb.LGBMClassifier(n_estimators=150, learning_rate=0.05, class_weight='balanced', random_state=42, verbose=-1),
            "XGBoost": xgb.XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=6, eval_metric='logloss', random_state=42, n_jobs=-1)
        }

        results = []
        feature_importance_dict = {}

        for name, clf in models.items():
            logging.info(f"Training {name}...")
            clf.fit(X_train, y_train)

            # Predict probabilities and classes
            if hasattr(clf, "predict_proba"):
                probs = clf.predict_proba(X_test)[:, 1]
            else:
                probs = clf.predict(X_test)
            preds = (probs >= 0.5).astype(int)

            roc_auc = roc_auc_score(y_test, probs)
            pr_auc = average_precision_score(y_test, probs)
            f1_macro = f1_score(y_test, preds, average='macro')
            f1_pos = f1_score(y_test, preds, pos_label=1)
            bal_acc = balanced_accuracy_score(y_test, preds)
            brier = brier_score_loss(y_test, probs)

            results.append({
                "Model": name,
                "ROC-AUC": round(roc_auc, 4),
                "PR-AUC": round(pr_auc, 4),
                "F1-Macro": round(f1_macro, 4),
                "F1-Exposed": round(f1_pos, 4),
                "Balanced-Acc": round(bal_acc, 4),
                "Brier-Score": round(brier, 4)
            })

            # Extract feature importance if available
            estimator = clf.named_steps['logisticregression'] if hasattr(clf, 'named_steps') else clf
            if hasattr(estimator, "feature_importances_"):
                importances = estimator.feature_importances_
                feature_importance_dict[name] = dict(sorted(
                    zip(feature_names, [round(float(v), 4) for v in importances]),
                    key=lambda x: x[1],
                    reverse=True
                )[:15])
            elif hasattr(estimator, "coef_"):
                importances = np.abs(estimator.coef_[0])
                feature_importance_dict[name] = dict(sorted(
                    zip(feature_names, [round(float(v), 4) for v in importances]),
                    key=lambda x: x[1],
                    reverse=True
                )[:15])

            logging.info(f"[{name}] ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f} | F1-Macro: {f1_macro:.4f}")

        results_df = pd.DataFrame(results).sort_values(by="ROC-AUC", ascending=False)
        
        # Save results
        metrics_csv = self.results_dir / "rq1_exposure_benchmarks.csv"
        results_df.to_csv(metrics_csv, index=False)

        feat_json = self.results_dir / "rq1_feature_importance.json"
        with open(feat_json, "w", encoding="utf-8") as f:
            json.dump(feature_importance_dict, f, indent=2)

        logging.info(f"Saved RQ1 results to {metrics_csv} and {feat_json}")
        return results_df

if __name__ == "__main__":
    trainer = ExposureModelTrainer("data/pilot", "results")
    results = trainer.run()
    print("\n=== RQ1: BINARY EXPOSURE PREDICTION BENCHMARK RESULTS ===")
    print(results.to_string(index=False))
