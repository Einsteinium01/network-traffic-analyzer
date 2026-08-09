"""
train_model.py
==============
WHY THIS FILE EXISTS
--------------------
This is the core ML training script for Phase 2.  It:
  1. Loads the clean parquet produced by prepare_dataset.py
  2. Selects feature columns (all numeric columns except 'label'/'attack_type')
  3. Splits into train/test sets (stratified to handle class imbalance)
  4. Trains a Random Forest classifier
  5. Evaluates: Accuracy, Precision, Recall, F1, Confusion Matrix
  6. Saves model.pkl and feature_columns.pkl for Phase 5 (Detection Engine)
  7. Saves a human-readable training report + confusion matrix image

HOW IT WORKS
------------
Random Forest builds many decision trees on random subsets of the data and
features, then aggregates their votes.  This makes it:
  - Robust to overfitting
  - Tolerant of feature-scale differences (no scaling needed)
  - Capable of returning per-class confidence scores (predict_proba)

FILE:    models/train_model.py
RUN:     python models/train_model.py
PREREQ:  Run prepare_dataset.py first to generate dataset/cicids2017_clean.parquet

EXPECTED OUTPUT
---------------
  models/model.pkl               – trained RandomForestClassifier
  models/feature_columns.pkl     – list of feature column names
  reports/training_report.txt    – classification metrics
  reports/confusion_matrix.png   – visual confusion matrix
"""

import sys
import json
import pathlib
import logging
import time

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")           # Non-interactive backend (no GUI required)
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parent.parent
CLEAN_DATA_PATH = ROOT / "dataset" / "cicids2017_clean.parquet"
MODEL_PATH = ROOT / "models" / "model.pkl"
FEATURES_PATH = ROOT / "models" / "feature_columns.pkl"
REPORT_DIR = ROOT / "reports"
LOG_PATH = ROOT / "logs" / "train_model.log"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Force UTF-8 on the console to avoid cp1252 errors on Windows
_stream_handler = logging.StreamHandler(sys.stdout)
if hasattr(_stream_handler.stream, "reconfigure"):
    _stream_handler.stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        _stream_handler,
        logging.FileHandler(LOG_PATH, mode="w", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hyperparameters
# ---------------------------------------------------------------------------
RANDOM_STATE = 42
TEST_SIZE = 0.20          # 80% train / 20% test
N_ESTIMATORS = 100        # Number of trees in the forest
MAX_FEATURES = "sqrt"     # Features considered per split (sqrt = good default)
N_JOBS = -1               # Use all CPU cores
MAX_SAMPLES = 0.5         # Use 50% of training rows per tree (speeds up on large datasets)


# ---------------------------------------------------------------------------
# Helper: load data
# ---------------------------------------------------------------------------
def load_data() -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Load the clean parquet, separate features from label."""
    if not CLEAN_DATA_PATH.exists():
        log.error("Clean dataset not found: %s", CLEAN_DATA_PATH)
        log.error("Please run:  python models/prepare_dataset.py  first.")
        sys.exit(1)

    log.info("Loading %s …", CLEAN_DATA_PATH)
    df = pd.read_parquet(CLEAN_DATA_PATH, engine="pyarrow")
    log.info("  Shape: %d rows × %d columns", *df.shape)

    # Feature columns: all numeric columns except label and attack_type
    exclude = {"label", "attack_type"}
    feature_cols = [
        c for c in df.columns
        if c not in exclude and pd.api.types.is_numeric_dtype(df[c])
    ]

    X = df[feature_cols]
    y = df["label"]

    log.info("  Features : %d", len(feature_cols))
    log.info("  Label distribution:\n%s",
             y.value_counts().rename({0: "BENIGN (0)", 1: "ATTACK (1)"}).to_string())

    return X, y, feature_cols


# ---------------------------------------------------------------------------
# Helper: train
# ---------------------------------------------------------------------------
def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    """Train a Random Forest classifier and return it."""
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_features=MAX_FEATURES,
        max_samples=MAX_SAMPLES,
        random_state=RANDOM_STATE,
        n_jobs=N_JOBS,
        class_weight="balanced",   # compensates for class imbalance automatically
        verbose=1,
    )
    log.info("Training Random Forest with %d estimators …", N_ESTIMATORS)
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    log.info("Training complete in %.1f seconds.", elapsed)
    return model


# ---------------------------------------------------------------------------
# Helper: evaluate
# ---------------------------------------------------------------------------
def evaluate(model: RandomForestClassifier,
             X_test: pd.DataFrame,
             y_test: pd.Series) -> dict:
    """Predict and compute all evaluation metrics."""
    log.info("Evaluating on test set (%d samples) …", len(y_test))
    y_pred = model.predict(X_test)

    metrics = {
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, average="binary"),
        "recall":    recall_score(y_test, y_pred, average="binary"),
        "f1_score":  f1_score(y_test, y_pred, average="binary"),
    }

    log.info("─" * 40)
    log.info("  Accuracy  : %.4f", metrics["accuracy"])
    log.info("  Precision : %.4f", metrics["precision"])
    log.info("  Recall    : %.4f", metrics["recall"])
    log.info("  F1 Score  : %.4f", metrics["f1_score"])
    log.info("─" * 40)
    log.info("Full classification report:\n%s",
             classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics["confusion_matrix"] = cm.tolist()
    return metrics, y_pred


# ---------------------------------------------------------------------------
# Helper: save confusion matrix plot
# ---------------------------------------------------------------------------
def save_confusion_matrix(cm: list, output_path: pathlib.Path) -> None:
    """Render a seaborn heatmap of the confusion matrix and save as PNG."""
    cm_arr = np.array(cm)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm_arr,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["BENIGN", "ATTACK"],
        yticklabels=["BENIGN", "ATTACK"],
        ax=ax,
    )
    ax.set_xlabel("Predicted Label", fontsize=12)
    ax.set_ylabel("True Label", fontsize=12)
    ax.set_title("Random Forest – Confusion Matrix (CICIDS2017)", fontsize=13)
    plt.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    log.info("Saved confusion matrix → %s", output_path)


# ---------------------------------------------------------------------------
# Helper: save feature importance plot
# ---------------------------------------------------------------------------
def save_feature_importance(model: RandomForestClassifier,
                             feature_cols: list[str],
                             output_path: pathlib.Path,
                             top_n: int = 20) -> None:
    """Bar chart of the top-N most important features."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    top_features = [feature_cols[i] for i in indices]
    top_importances = importances[indices]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(range(top_n), top_importances[::-1], align="center", color="#2196F3")
    ax.set_yticks(range(top_n))
    ax.set_yticklabels(top_features[::-1], fontsize=9)
    ax.set_xlabel("Feature Importance (Gini)", fontsize=12)
    ax.set_title(f"Top {top_n} Features – Random Forest", fontsize=13)
    plt.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    log.info("Saved feature importance plot → %s", output_path)


# ---------------------------------------------------------------------------
# Helper: save text report
# ---------------------------------------------------------------------------
def save_report(metrics: dict, feature_cols: list[str], report_path: pathlib.Path) -> None:
    """Write a human-readable training summary."""
    lines = [
        "=" * 65,
        "Intelligent Network Traffic Analyzer – Training Report",
        "=" * 65,
        f"Model          : Random Forest",
        f"Dataset        : CICIDS2017 (binary: BENIGN vs ATTACK)",
        f"Features used  : {len(feature_cols)}",
        f"Hyperparameters:",
        f"  n_estimators : {N_ESTIMATORS}",
        f"  max_features : {MAX_FEATURES}",
        f"  max_samples  : {MAX_SAMPLES}",
        f"  class_weight : balanced",
        f"  test_size    : {TEST_SIZE}",
        "",
        "Evaluation Metrics (Test Set)",
        "-" * 40,
        f"  Accuracy  : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)",
        f"  Precision : {metrics['precision']:.4f}",
        f"  Recall    : {metrics['recall']:.4f}",
        f"  F1 Score  : {metrics['f1_score']:.4f}",
        "",
        "Confusion Matrix (rows=True, cols=Predicted)",
        "-" * 40,
        f"  [[TN  FP]     {metrics['confusion_matrix'][0]}",
        f"   [FN  TP]]    {metrics['confusion_matrix'][1]}",
        "",
        "Saved Artefacts",
        "-" * 40,
        f"  models/model.pkl",
        f"  models/feature_columns.pkl",
        f"  reports/confusion_matrix.png",
        f"  reports/feature_importance.png",
        "=" * 65,
    ]
    text = "\n".join(lines)
    report_path.write_text(text, encoding="utf-8")
    log.info("Saved training report → %s", report_path)
    print("\n" + text)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 70)
    log.info("Phase 2 – Random Forest Training")
    log.info("=" * 70)

    # Load data
    X, y, feature_cols = load_data()

    # Stratified train/test split (preserves class ratio)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    log.info("Train: %d samples | Test: %d samples", len(X_train), len(X_test))

    # Train
    model = train_random_forest(X_train, y_train)

    # Evaluate
    metrics, _y_pred = evaluate(model, X_test, y_test)

    # Save model artefacts
    joblib.dump(model, MODEL_PATH)
    log.info("Saved model → %s", MODEL_PATH)

    joblib.dump(feature_cols, FEATURES_PATH)
    log.info("Saved feature columns → %s", FEATURES_PATH)

    # Save visualisations + report
    save_confusion_matrix(metrics["confusion_matrix"], REPORT_DIR / "confusion_matrix.png")
    save_feature_importance(model, feature_cols, REPORT_DIR / "feature_importance.png")
    save_report(metrics, feature_cols, REPORT_DIR / "training_report.txt")

    log.info("=" * 70)
    log.info("Phase 2 complete!  Proceed to Phase 3 – Packet Capture.")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
