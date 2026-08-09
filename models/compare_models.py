"""
compare_models.py
=================
WHY THIS FILE EXISTS
--------------------
The project spec asks us to compare Random Forest, XGBoost, and Decision Tree
and save the *best* model as model.pkl.  This script does exactly that — in one
run — so the decision is data-driven rather than assumed.

HOW IT WORKS
------------
1. Loads the clean parquet (produced by prepare_dataset.py).
2. Uses the SAME stratified 80/20 split across all three models (same random
   seed) so comparison is fair.
3. Trains:
     a. RandomForestClassifier (scikit-learn, n_jobs=-1, all CPU cores)
     b. XGBClassifier          (XGBoost, device="cuda" → GTX 1650 GPU)
     c. DecisionTreeClassifier (scikit-learn, single tree baseline)
4. Evaluates Accuracy, Precision, Recall, F1 on the shared test set.
5. Prints a side-by-side comparison table.
6. Saves individual plots + a combined bar chart.
7. Writes reports/comparison_report.txt.
8. **Promotes the best model** to models/model.pkl and models/feature_columns.pkl
   (overwrites the file if a better model is found).

FILE:    models/compare_models.py
RUN:     python models/compare_models.py
PREREQ:  prepare_dataset.py must have run first.

EXPECTED OUTPUT
---------------
  reports/comparison_report.txt     – side-by-side metric table
  reports/comparison_bar_chart.png  – grouped bar chart of all metrics
  reports/cm_random_forest.png      – confusion matrix for RF
  reports/cm_xgboost.png            – confusion matrix for XGBoost
  reports/cm_decision_tree.png      – confusion matrix for DT
  models/model.pkl                  – BEST model (may overwrite RF)
  models/feature_columns.pkl        – feature list (unchanged)
  logs/compare_models.log
"""

import sys
import time
import pathlib
import logging

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report,
)
import xgboost as xgb

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = pathlib.Path(__file__).resolve().parent.parent
DATA_PATH   = ROOT / "dataset" / "cicids2017_clean.parquet"
MODEL_PATH  = ROOT / "models" / "model.pkl"
FEATS_PATH  = ROOT / "models" / "feature_columns.pkl"
REPORT_DIR  = ROOT / "reports"
LOG_PATH    = ROOT / "logs" / "compare_models.log"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

_sh = logging.StreamHandler(sys.stdout)
if hasattr(_sh.stream, "reconfigure"):
    _sh.stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[_sh, logging.FileHandler(LOG_PATH, mode="w", encoding="utf-8")],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
RANDOM_STATE = 42
TEST_SIZE    = 0.20


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_data() -> tuple:
    if not DATA_PATH.exists():
        log.error("Clean dataset not found: %s", DATA_PATH)
        log.error("Run:  python models/prepare_dataset.py  first.")
        sys.exit(1)

    log.info("Loading %s ...", DATA_PATH.name)
    df = pd.read_parquet(DATA_PATH, engine="pyarrow")
    log.info("  Shape: %d rows x %d columns", *df.shape)

    exclude = {"label", "attack_type"}
    feature_cols = [
        c for c in df.columns
        if c not in exclude and pd.api.types.is_numeric_dtype(df[c])
    ]
    X = df[feature_cols]
    y = df["label"]
    log.info("  Features: %d  |  BENIGN: %d  |  ATTACK: %d",
             len(feature_cols), (y == 0).sum(), (y == 1).sum())
    return X, y, feature_cols


# ---------------------------------------------------------------------------
# Model definitions
# ---------------------------------------------------------------------------
def build_models() -> list[tuple]:
    """
    Return list of (name, model) tuples.
    XGBoost uses device='cuda' for GPU acceleration on the GTX 1650.
    Decision Tree uses no depth limit so we can see raw tree power.
    """
    rf = RandomForestClassifier(
        n_estimators=100,
        max_features="sqrt",
        max_samples=0.5,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=0,
    )

    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=4.9,   # ~ratio of BENIGN/ATTACK to handle imbalance
        device="cuda",           # <<< GTX 1650 GPU
        tree_method="hist",      # histogram-based: fastest on GPU
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        verbosity=1,
    )

    dt = DecisionTreeClassifier(
        max_depth=20,            # deep enough to capture patterns
        class_weight="balanced",
        random_state=RANDOM_STATE,
    )

    return [
        ("Random Forest (CPU)", rf),
        ("XGBoost (GPU)",       xgb_model),
        ("Decision Tree (CPU)", dt),
    ]


# ---------------------------------------------------------------------------
# Training + evaluation loop
# ---------------------------------------------------------------------------
def train_and_evaluate(models, X_train, X_test, y_train, y_test) -> list[dict]:
    results = []

    for name, model in models:
        log.info("")
        log.info("=" * 60)
        log.info("  Training: %s", name)
        log.info("=" * 60)

        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0
        log.info("  Finished in %.1f seconds.", train_time)

        log.info("  Evaluating ...")
        y_pred = model.predict(X_test)

        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="binary", zero_division=0)
        rec  = recall_score(y_test, y_pred, average="binary", zero_division=0)
        f1   = f1_score(y_test, y_pred, average="binary", zero_division=0)
        cm   = confusion_matrix(y_test, y_pred)

        log.info("  Accuracy : %.4f  Precision: %.4f  Recall: %.4f  F1: %.4f",
                 acc, prec, rec, f1)
        log.info("  Classification report:\n%s",
                 classification_report(y_test, y_pred,
                                       target_names=["BENIGN", "ATTACK"],
                                       zero_division=0))

        results.append({
            "name":       name,
            "model":      model,
            "accuracy":   acc,
            "precision":  prec,
            "recall":     rec,
            "f1_score":   f1,
            "train_time": train_time,
            "cm":         cm,
        })

    return results


# ---------------------------------------------------------------------------
# Plotting helpers
# ---------------------------------------------------------------------------
def _plot_confusion_matrix(cm: np.ndarray, title: str, path: pathlib.Path) -> None:
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["BENIGN", "ATTACK"],
                yticklabels=["BENIGN", "ATTACK"], ax=ax)
    ax.set_xlabel("Predicted", fontsize=11)
    ax.set_ylabel("True", fontsize=11)
    ax.set_title(title, fontsize=12)
    plt.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    log.info("  Saved confusion matrix -> %s", path.name)


def save_confusion_matrices(results: list[dict]) -> None:
    slug_map = {
        "Random Forest (CPU)": "random_forest",
        "XGBoost (GPU)":       "xgboost",
        "Decision Tree (CPU)": "decision_tree",
    }
    for r in results:
        slug = slug_map.get(r["name"], r["name"].lower().replace(" ", "_"))
        _plot_confusion_matrix(
            r["cm"],
            f"Confusion Matrix – {r['name']}",
            REPORT_DIR / f"cm_{slug}.png",
        )


def save_comparison_chart(results: list[dict]) -> None:
    """Grouped bar chart comparing all metrics across all models."""
    metrics   = ["accuracy", "precision", "recall", "f1_score"]
    labels    = [r["name"] for r in results]
    x         = np.arange(len(metrics))
    width     = 0.25
    colours   = ["#2196F3", "#FF6F00", "#4CAF50"]

    fig, ax = plt.subplots(figsize=(10, 6))
    for i, (result, colour) in enumerate(zip(results, colours)):
        values = [result[m] for m in metrics]
        bars   = ax.bar(x + i * width, values, width, label=result["name"], color=colour)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                    f"{val:.4f}", ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x + width)
    ax.set_xticklabels(["Accuracy", "Precision", "Recall", "F1 Score"], fontsize=12)
    ax.set_ylim(0.95, 1.005)
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Model Comparison – CICIDS2017 Binary Classification", fontsize=13)
    ax.legend(fontsize=10)
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.3f}"))
    plt.tight_layout()
    fig.savefig(REPORT_DIR / "comparison_bar_chart.png", dpi=150)
    plt.close(fig)
    log.info("Saved comparison chart -> comparison_bar_chart.png")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def save_text_report(results: list[dict]) -> None:
    best = max(results, key=lambda r: r["f1_score"])

    sep  = "-" * 68
    hdrs = f"{'Model':<25} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1':>8} {'Time(s)':>9}"
    rows = [
        f"{r['name']:<25} {r['accuracy']:>9.4f} {r['precision']:>10.4f} "
        f"{r['recall']:>8.4f} {r['f1_score']:>8.4f} {r['train_time']:>9.1f}"
        for r in results
    ]

    text = "\n".join([
        "=" * 68,
        "  Network Traffic Analyzer – Model Comparison Report",
        "=" * 68,
        f"  Dataset        : CICIDS2017 (binary: BENIGN vs ATTACK)",
        f"  Train/Test     : 80% / 20%  (stratified, seed=42)",
        f"  Training rows  : ~2,016,638  |  Test rows: ~504,160",
        "=" * 68,
        "",
        hdrs,
        sep,
        *rows,
        sep,
        "",
        f"  >> WINNER: {best['name']}  (F1 = {best['f1_score']:.4f})",
        f"  >> Saved as models/model.pkl",
        "",
        "Confusion Matrices saved to reports/",
        "Bar chart saved to reports/comparison_bar_chart.png",
        "=" * 68,
    ])

    path = REPORT_DIR / "comparison_report.txt"
    path.write_text(text, encoding="utf-8")
    log.info("Saved comparison report -> %s", path)
    print("\n" + text)


# ---------------------------------------------------------------------------
# Promote best model
# ---------------------------------------------------------------------------
def promote_best(results: list[dict], feature_cols: list[str]) -> None:
    best = max(results, key=lambda r: r["f1_score"])
    log.info("")
    log.info("Best model: %s  (F1=%.4f)", best["name"], best["f1_score"])
    joblib.dump(best["model"], MODEL_PATH)
    joblib.dump(feature_cols, FEATS_PATH)
    log.info("Promoted -> models/model.pkl")
    log.info("Promoted -> models/feature_columns.pkl")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 65)
    log.info("Model Comparison: Random Forest | XGBoost (GPU) | Decision Tree")
    log.info("=" * 65)

    # Load
    X, y, feature_cols = load_data()

    # Split (same seed for all models = fair comparison)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE,
    )
    log.info("Train: %d  |  Test: %d", len(X_train), len(X_test))

    # Build + train + evaluate
    models  = build_models()
    results = train_and_evaluate(models, X_train, X_test, y_train, y_test)

    # Plots
    save_confusion_matrices(results)
    save_comparison_chart(results)

    # Report
    save_text_report(results)

    # Save best
    promote_best(results, feature_cols)

    log.info("")
    log.info("Comparison complete.  Ready for Phase 3 – Packet Capture.")


if __name__ == "__main__":
    main()
