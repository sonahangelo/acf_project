"""
ai_model.py -- AI Detection Engine

MVP uses scikit-learn's IsolationForest (unsupervised, no labels needed).
Features are scaled (StandardScaler) before training/prediction, since
IsolationForest is sensitive to feature magnitude -- without scaling,
large-range features like port numbers dominate over small-range but
meaningful features like scan_distinct_ports.

Also stores per-feature mean/std from training so we can explain *why*
a given packet looked anomalous (simple deviation-from-normal heuristic).
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import MODEL_FEATURE_COLUMNS


class AnomalyModel:
    def __init__(self, contamination=0.02, model_path="models/anomaly_model.pkl"):
        self.contamination = contamination
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_means = {}
        self.feature_stds = {}

    def train(self, db_path):
        import sqlite3
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query("SELECT * FROM traffic", conn)
        conn.close()
        if df.empty:
            raise ValueError(f"No data found in {db_path} -- capture some traffic first.")

        X = df[MODEL_FEATURE_COLUMNS].fillna(0)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        self.model.fit(X_scaled)

        self.feature_means = X.mean().to_dict()
        self.feature_stds = X.std().replace(0, 1).to_dict()

        self.save()
        print(f"[ai_model] Trained on {len(df)} rows, saved to {self.model_path}")

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
        }, self.model_path)

    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"No trained model at {self.model_path}. Run: python ai_model.py --train"
            )
        bundle = joblib.load(self.model_path)
        self.model = bundle["model"]
        self.scaler = bundle["scaler"]
        self.feature_means = bundle["feature_means"]
        self.feature_stds = bundle["feature_stds"]
        return self

    def predict(self, feature_vector):
        """
        feature_vector: list matching MODEL_FEATURE_COLUMNS order.
        Returns (label, score) where label is -1 (anomaly) or 1 (normal).
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load() or train() first.")
        X = pd.DataFrame([feature_vector], columns=MODEL_FEATURE_COLUMNS)
        X_scaled = self.scaler.transform(X)
        label = self.model.predict(X_scaled)[0]
        score = self.model.decision_function(X_scaled)[0]
        return label, score

    def explain(self, feature_vector, top_n=3):
        """
        Returns a list of (feature_name, value, deviation_in_stds) for the
        top_n features that deviate most from the training-data average.
        A simple, honest heuristic -- not a true SHAP explanation -- but
        cheap and gives a human a real reason to look at.
        """
        deviations = []
        for name, value in zip(MODEL_FEATURE_COLUMNS, feature_vector):
            mean = self.feature_means.get(name, 0)
            std = self.feature_stds.get(name, 1) or 1
            z = (value - mean) / std
            deviations.append((name, value, round(z, 2)))

        deviations.sort(key=lambda d: abs(d[2]), reverse=True)
        return deviations[:top_n]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true", help="Train on data/traffic_log.csv")
    parser.add_argument("--db", default="data/acf.db")
    args = parser.parse_args()

    if args.train:
        m = AnomalyModel()
        m.train(args.db)
