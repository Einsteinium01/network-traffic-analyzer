"""
Phase 1 setup verifier.

WHY THIS FILE EXISTS
--------------------
Phase 1 produces no user-visible feature, so there is nothing to "click" to
prove it worked. This script is the test for Phase 1: it checks that the folder
structure, the config module, the dependencies, and the dataset are all in the
state the later phases expect.

HOW TO RUN
----------
    python scripts/verify_setup.py

EXPECTED OUTPUT
---------------
A checklist. Green [ OK ] lines are fine. [WARN] lines are expected until you
paste the dataset. [FAIL] lines mean something in the setup needs fixing.
"""

import importlib
import sys
from pathlib import Path

# Make the project root importable so `import config.settings` works even
# though this script lives one level down in scripts/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import settings  # noqa: E402  (import must follow the sys.path fix)

REQUIRED_DIRECTORIES = [
    "dataset",
    "models",
    "packet_capture",
    "backend",
    "frontend",
    "templates",
    "static",
    "database",
    "logs",
    "tests",
    "reports",
    "config",
    "scripts",
]

# Import name -> friendly name, because the module you import is not always
# the name you pip-install (e.g. `sklearn` comes from `scikit-learn`).
REQUIRED_PACKAGES = {
    "flask": "Flask",
    "flask_socketio": "Flask-SocketIO",
    "flask_cors": "Flask-Cors",
    "scapy": "scapy",
    "sklearn": "scikit-learn",
    "pandas": "pandas",
    "numpy": "numpy",
    "joblib": "joblib",
    "matplotlib": "matplotlib",
    "dotenv": "python-dotenv",
    "pytest": "pytest",
}

failures = 0
warnings = 0


def report(status: str, message: str) -> None:
    """Print one checklist line and tally failures/warnings."""
    global failures, warnings
    if status == "FAIL":
        failures += 1
    elif status == "WARN":
        warnings += 1
    print(f"[{status:^4}] {message}")


def check_python_version() -> None:
    """The project targets Python 3.12+ (uses modern typing and pathlib APIs)."""
    major, minor = sys.version_info[:2]
    version = f"{major}.{minor}.{sys.version_info[2]}"
    if (major, minor) >= (3, 12):
        report("OK", f"Python {version}")
    else:
        report("FAIL", f"Python {version} found, but 3.12+ is required")


def check_virtual_environment() -> None:
    """Warn if packages would be installed into the system Python."""
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if in_venv:
        report("OK", f"Virtual environment active ({sys.prefix})")
    else:
        report("WARN", "No virtual environment detected - see README step 2")


def check_directories() -> None:
    """Every later phase writes into one of these folders."""
    for name in REQUIRED_DIRECTORIES:
        path = PROJECT_ROOT / name
        if path.is_dir():
            report("OK", f"Folder exists: {name}/")
        else:
            report("FAIL", f"Missing folder: {name}/")


def check_packages() -> None:
    """Confirm requirements.txt was actually installed."""
    for module_name, package_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            report("FAIL", f"Package not installed: {package_name}")
        else:
            report("OK", f"Package importable: {package_name}")


def check_config() -> None:
    """Ensure config.settings loads and its runtime folders exist."""
    settings.ensure_directories()
    report("OK", f"Config loaded, project root = {settings.BASE_DIR}")


def check_dataset() -> None:
    """The dataset is pasted by hand, so its absence is a warning, not an error."""
    csv_files = list(settings.DATASET_DIR.rglob("*.csv"))
    if csv_files:
        total_mb = sum(f.stat().st_size for f in csv_files) / (1024 * 1024)
        report("OK", f"Dataset: {len(csv_files)} CSV file(s), {total_mb:.1f} MB total")
    else:
        report("WARN", "No CSV files in dataset/ yet - see dataset/README.md")


def main() -> int:
    print("=" * 62)
    print(" Intelligent Network Traffic Analyzer - Phase 1 verification")
    print("=" * 62)

    for section, check in (
        ("Environment", check_python_version),
        (None, check_virtual_environment),
        ("Folder structure", check_directories),
        ("Dependencies", check_packages),
        ("Configuration", check_config),
        ("Dataset", check_dataset),
    ):
        if section:
            print(f"\n--- {section} ---")
        check()

    print("\n" + "=" * 62)
    if failures:
        print(f" RESULT: {failures} problem(s) found. Fix them before Phase 2.")
    elif warnings:
        print(f" RESULT: setup is valid ({warnings} warning(s) - safe to continue).")
    else:
        print(" RESULT: setup is complete. Ready for Phase 2.")
    print("=" * 62)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
