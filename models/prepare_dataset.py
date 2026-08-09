"""
prepare_dataset.py
==================
WHY THIS FILE EXISTS
--------------------
The CICIDS2017 dataset ships as 8 raw CSV files (~885 MB total) with
inconsistent column names, infinite values, NaN rows, and a highly
imbalanced label column.  This script normalises everything into a
single clean file that train_model.py can load instantly.

HOW IT WORKS
------------
1. Reads all CSVs from dataset/CICIDS2017/ in one pass.
2. Strips leading/trailing whitespace from column names (CICIDS2017 has
   a known space-prefix bug in several files).
3. Drops constant columns, duplicate rows, and any row with an infinite
   or NaN feature value.
4. Maps all non-BENIGN labels to "Attack" so we get a binary problem.
5. Saves the result to dataset/cicids2017_clean.parquet – a columnar
   format that loads ~10x faster than CSV on the next run.

FILE: models/prepare_dataset.py
RUN:  python models/prepare_dataset.py
"""

import sys
import pathlib
import logging
import pandas as pd
import numpy as np

# ---------------------------------------------------------------------------
# Paths (resolved relative to project root regardless of cwd)
# ---------------------------------------------------------------------------
ROOT = pathlib.Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "dataset" / "CICIDS2017"
OUTPUT_PATH = ROOT / "dataset" / "cicids2017_clean.parquet"
LOG_PATH = ROOT / "logs" / "prepare_dataset.log"

# ---------------------------------------------------------------------------
# Logging: write to both the console and a log file
# ---------------------------------------------------------------------------
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
# Force UTF-8 on the console stream so arrow chars don't crash on Windows cp1252
_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.stream.reconfigure(encoding="utf-8") if hasattr(_stream_handler.stream, "reconfigure") else None

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
# CICIDS2017 columns we know are useful for ML
# (these exist in every file after name-normalisation)
# ---------------------------------------------------------------------------
# We will load ALL columns and then drop the ones that are:
#   - constant        (zero variance → no predictive power)
#   - infinite        (Scapy-captured flows sometimes generate Inf bps)
#   - NaN             (missing values)


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names (CICIDS2017 quirk)."""
    df.columns = [c.strip() for c in df.columns]
    return df


def load_all_csvs(directory: pathlib.Path) -> pd.DataFrame:
    """Read every CSV in *directory* and concatenate into one DataFrame."""
    csv_files = sorted(directory.glob("*.csv"))
    if not csv_files:
        log.error("No CSV files found in %s", directory)
        sys.exit(1)

    frames = []
    for csv_path in csv_files:
        log.info("Loading %s (%.1f MB) …", csv_path.name, csv_path.stat().st_size / 1e6)
        try:
            df = pd.read_csv(
                csv_path,
                encoding="utf-8",
                low_memory=False,
            )
            df = normalise_columns(df)
            frames.append(df)
            log.info("  -> %d rows, %d columns", len(df), len(df.columns))
        except Exception as exc:
            log.warning("  Skipped %s: %s", csv_path.name, exc)

    combined = pd.concat(frames, axis=0, ignore_index=True)
    log.info("Combined dataset: %d rows x %d columns", *combined.shape)
    return combined


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply all cleaning steps in order:
      1. Identify the label column
      2. Replace ±Inf with NaN so we can drop them uniformly
      3. Drop rows with any NaN in feature columns
      4. Drop duplicate rows
      5. Drop constant (zero-variance) feature columns
    """

    # ── 1. Identify label column ────────────────────────────────────────────
    label_col = None
    for candidate in ["Label", "label"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        log.error("Could not find a 'Label' column.  Columns: %s", list(df.columns[:10]))
        sys.exit(1)

    log.info("Label column: '%s'", label_col)
    log.info("Raw label distribution:\n%s", df[label_col].value_counts().to_string())

    # ── 2. Replace Inf/-Inf with NaN ────────────────────────────────────────
    feature_cols = [c for c in df.columns if c != label_col]
    numeric_cols = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()

    before = len(df)
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # ── 3. Drop NaN rows (in numeric feature columns only) ──────────────────
    df = df.dropna(subset=numeric_cols)
    log.info("Dropped %d rows with NaN/Inf values", before - len(df))

    # ── 4. Drop exact duplicate rows ─────────────────────────────────────────
    before = len(df)
    df = df.drop_duplicates()
    log.info("Dropped %d duplicate rows", before - len(df))

    # ── 5. Drop constant columns ─────────────────────────────────────────────
    constant_cols = [c for c in numeric_cols if df[c].nunique() <= 1]
    if constant_cols:
        log.info("Dropping %d constant columns: %s", len(constant_cols), constant_cols)
        df = df.drop(columns=constant_cols)

    log.info("Clean dataset: %d rows x %d columns", *df.shape)
    return df, label_col


def encode_labels(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """
    Map to binary: BENIGN → 0, everything else → 1.
    Also add a human-readable 'label_str' column for reference.
    """
    df = df.copy()

    # Keep original attack name in a separate column
    df["attack_type"] = df[label_col].str.strip()

    # Binary encoding: 0 = Normal, 1 = Attack
    df["label"] = (df["attack_type"].str.upper() != "BENIGN").astype(int)

    # Drop the original label column (replaced by 'label' + 'attack_type')
    df = df.drop(columns=[label_col])

    log.info("Binary label distribution:\n%s",
             df["label"].value_counts().rename({0: "BENIGN (0)", 1: "ATTACK (1)"}).to_string())
    return df


def save_parquet(df: pd.DataFrame, path: pathlib.Path) -> None:
    """Save to parquet. Create parent dir if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False, engine="pyarrow")
    log.info("Saved clean dataset -> %s (%.1f MB)", path, path.stat().st_size / 1e6)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 70)
    log.info("CICIDS2017 Dataset Preparation")
    log.info("=" * 70)

    if not DATASET_DIR.exists():
        log.error("Dataset directory not found: %s", DATASET_DIR)
        sys.exit(1)

    # Load
    df = load_all_csvs(DATASET_DIR)

    # Clean
    df, label_col = clean_dataset(df)

    # Encode labels
    df = encode_labels(df, label_col)

    # Save
    save_parquet(df, OUTPUT_PATH)

    log.info("=" * 70)
    log.info("Preparation complete!  Run train_model.py next.")
    log.info("=" * 70)


if __name__ == "__main__":
    main()
