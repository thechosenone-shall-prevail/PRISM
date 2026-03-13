"""
PRISM — ML Model Training Pipeline
Trains an XGBoost classifier for APT group attribution.

Usage:
    python ml/train_model.py

Expects:
    ml/data/training_data.csv (from generate_training_data.py)
    ml/data/feature_schema.json

Outputs:
    ml/models/PRISM_model.pkl
    ml/models/feature_schema.json (copied for backend)
    ml/models/training_metrics.json
"""

import json
import shutil
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
import joblib

warnings.filterwarnings("ignore")

ML_DIR = Path(__file__).resolve().parent
DATA_DIR = ML_DIR / "data"
MODEL_DIR = ML_DIR / "models"

TRAINING_DATA_PATH = DATA_DIR / "training_data.csv"
FEATURE_SCHEMA_PATH = DATA_DIR / "feature_schema.json"


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # 1. Load data
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("PRISM ML Model Training Pipeline")
    print("=" * 60)

    if not TRAINING_DATA_PATH.exists():
        print(f"ERROR: Training data not found at {TRAINING_DATA_PATH}")
        print("Run: python ml/generate_training_data.py first")
        return

    df = pd.read_csv(TRAINING_DATA_PATH)
    print(f"\nDataset: {len(df)} samples, {len(df.columns) - 1} features")

    with open(FEATURE_SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)

    feature_names = schema["features"]
    class_names = schema["class_names"]

    X = df[feature_names].values
    y_raw = df["label"].values

    # Encode labels
    le = LabelEncoder()
    le.fit(class_names)
    y = le.transform(y_raw)

    print(f"Classes: {len(class_names)}")
    print(f"Features: {X.shape[1]}")

    # -------------------------------------------------------------------------
    # 2. Train/test split
    # -------------------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}, Test: {len(X_test)}")

    # -------------------------------------------------------------------------
    # 3. Train XGBoost
    # -------------------------------------------------------------------------
    print("\nTraining XGBoost classifier...")

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        objective="multi:softprob",
        num_class=len(class_names),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # -------------------------------------------------------------------------
    # 4. Evaluate
    # -------------------------------------------------------------------------
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    weighted_f1 = f1_score(y_test, y_pred, average="weighted")

    print(f"\n{'=' * 60}")
    print(f"RESULTS")
    print(f"{'=' * 60}")
    print(f"Accuracy:     {accuracy:.4f}")
    print(f"Macro F1:     {macro_f1:.4f}")
    print(f"Weighted F1:  {weighted_f1:.4f}")

    # Per-class report
    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        output_dict=True,
    )
    report_text = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
    )
    print(f"\nPer-class Report:\n{report_text}")

    # -------------------------------------------------------------------------
    # 5. Cross-validation
    # -------------------------------------------------------------------------
    print("Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="f1_macro", n_jobs=-1)
    print(f"CV F1 (macro): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # -------------------------------------------------------------------------
    # 6. Feature importance
    # -------------------------------------------------------------------------
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:30]
    print(f"\nTop 30 most important features:")
    for rank, idx in enumerate(top_indices):
        print(f"  {rank+1:2d}. {feature_names[idx]}: {importances[idx]:.4f}")

    # -------------------------------------------------------------------------
    # 7. Export model
    # -------------------------------------------------------------------------
    model_path = MODEL_DIR / "PRISM_model.pkl"
    joblib.dump(model, model_path)
    print(f"\n✓ Model saved: {model_path}")

    # Copy + update feature schema to models dir
    schema_out = dict(schema)
    schema_out["model_version"] = "v1.0.0"
    schema_out["class_names"] = list(le.classes_)
    
    schema_out_path = MODEL_DIR / "feature_schema.json"
    with open(schema_out_path, "w", encoding="utf-8") as f:
        json.dump(schema_out, f, indent=2)
    print(f"✓ Feature schema: {schema_out_path}")

    # Training metrics
    per_class_metrics = {}
    for cls in le.classes_:
        if cls in report:
            per_class_metrics[cls] = {
                "precision": round(report[cls]["precision"], 4),
                "recall": round(report[cls]["recall"], 4),
                "f1": round(report[cls]["f1-score"], 4),
                "support": int(report[cls]["support"]),
            }

    metrics = {
        "model_version": "v1.0.0",
        "model_type": "xgboost",
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "cv_f1_std": round(float(cv_scores.std()), 4),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_count": len(feature_names),
        "class_count": len(class_names),
        "per_class_metrics": per_class_metrics,
        "top_features": [
            {"feature": feature_names[idx], "importance": round(float(importances[idx]), 4)}
            for idx in top_indices
        ],
        "hyperparameters": {
            "n_estimators": 300,
            "max_depth": 8,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
        },
    }

    metrics_path = MODEL_DIR / "training_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"✓ Metrics: {metrics_path}")

    print(f"\n{'=' * 60}")
    print("Training complete! Model ready for deployment.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
