"""
retrain.py
==========
WHY THIS FILE EXISTS
--------------------
Provides a single-command shortcut to re-run the full training pipeline
(prepare → train).  Useful when you want to re-train after adding new
data, changing hyperparameters, or switching from Random Forest to XGBoost.

HOW IT WORKS
------------
Calls prepare_dataset.py and then train_model.py as sub-processes so that
each script runs in its own clean namespace.  All logs and reports are
written by the individual scripts.

FILE: models/retrain.py
RUN:  python models/retrain.py
      python models/retrain.py --skip-prep   # if parquet already exists
"""

import argparse
import subprocess
import sys
import pathlib
import logging

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYTHON = sys.executable  # Reuse the same virtual-env interpreter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


def run_script(script_path: pathlib.Path) -> None:
    """Run a Python script as a sub-process; abort on failure."""
    log.info("Running: %s", script_path)
    result = subprocess.run(
        [PYTHON, str(script_path)],
        cwd=str(ROOT),
    )
    if result.returncode != 0:
        log.error("Script %s failed with exit code %d", script_path.name, result.returncode)
        sys.exit(result.returncode)
    log.info("✓ %s completed successfully.", script_path.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-train the traffic classifier.")
    parser.add_argument(
        "--skip-prep",
        action="store_true",
        help="Skip dataset preparation (use existing cicids2017_clean.parquet).",
    )
    args = parser.parse_args()

    log.info("=" * 65)
    log.info("Network Traffic Analyzer – Full Retrain Pipeline")
    log.info("=" * 65)

    if not args.skip_prep:
        run_script(ROOT / "models" / "prepare_dataset.py")
    else:
        log.info("Skipping prepare_dataset.py (--skip-prep flag set).")

    run_script(ROOT / "models" / "train_model.py")

    log.info("=" * 65)
    log.info("Retrain pipeline finished.  Check reports/ for results.")
    log.info("=" * 65)


if __name__ == "__main__":
    main()
