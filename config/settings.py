"""
Central configuration for the Intelligent Network Traffic Analyzer.

WHY THIS FILE EXISTS
--------------------
Every module needs to know things like "where is the database?" or "which
network interface should I sniff on?". Hard-coding those values in ten
different files means changing them in ten places later. Instead, every path
and tunable number lives here, and the rest of the project imports from it.

Values can be overridden without editing code by setting an environment
variable of the same name (optionally via a local `.env` file).
"""

import os
from pathlib import Path

# Guarded so that scripts/verify_setup.py can still run (and tell you what is
# missing) on a machine where requirements.txt has not been installed yet.
try:
    from dotenv import load_dotenv

    load_dotenv()  # Load key=value pairs from a local .env file if one exists.
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# BASE_DIR points at the project root (the folder containing this `config/`).
# Building every other path from it means the project works no matter which
# directory you launch it from.
BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_DIR = BASE_DIR / "dataset"
MODELS_DIR = BASE_DIR / "models"
DATABASE_DIR = BASE_DIR / "database"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
FRONTEND_BUILD_DIR = BASE_DIR / "frontend" / "dist"

MODEL_PATH = MODELS_DIR / "model.pkl"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.pkl"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
DATABASE_PATH = DATABASE_DIR / "traffic.db"
LOG_FILE_PATH = LOGS_DIR / "app.log"

# ---------------------------------------------------------------------------
# Flask / Socket.IO
# ---------------------------------------------------------------------------
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"

# Only used to sign session cookies. This project runs on localhost only, so a
# development default is acceptable; override it via the environment if needed.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")

# The Vite dev server runs on a different port than Flask, so the browser
# treats it as a different origin. These entries tell Flask to accept it.
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

# ---------------------------------------------------------------------------
# Packet capture
# ---------------------------------------------------------------------------
# None means "let Scapy pick the default interface". Set CAPTURE_INTERFACE in
# your .env once you know the exact name (Phase 3 includes a listing helper).
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE") or None

# A BPF filter applied in the kernel, before packets ever reach Python. Keeping
# it narrow is the cheapest possible performance win.
CAPTURE_BPF_FILTER = os.getenv("CAPTURE_BPF_FILTER", "ip and (tcp or udp or icmp)")

# How many recent packets the dashboard keeps in memory for the live table.
LIVE_PACKET_BUFFER_SIZE = 200

# ---------------------------------------------------------------------------
# Flow aggregation (Phase 4)
# ---------------------------------------------------------------------------
# A "flow" is all packets sharing (src IP, src port, dst IP, dst port, protocol).
# A flow is considered finished after this many seconds without new packets.
FLOW_TIMEOUT_SECONDS = float(os.getenv("FLOW_TIMEOUT_SECONDS", "15"))

# Even for a still-active flow, emit features this often so the dashboard is
# not silent during a long-running download.
FLOW_ACTIVE_EMIT_SECONDS = float(os.getenv("FLOW_ACTIVE_EMIT_SECONDS", "5"))

# ---------------------------------------------------------------------------
# Detection (Phase 5)
# ---------------------------------------------------------------------------
# A prediction is only raised as an alert if the model is at least this sure.
# Raising this number reduces false positives but may hide weak attacks.
ALERT_CONFIDENCE_THRESHOLD = float(os.getenv("ALERT_CONFIDENCE_THRESHOLD", "0.70"))

# The label the model uses for harmless traffic in the CICIDS2017 dataset.
BENIGN_LABEL = "BENIGN"

# ---------------------------------------------------------------------------
# Scan / PortScan heuristic detection (Phase 5 — complements the ML layer)
# ---------------------------------------------------------------------------
# Rapid port scans are made of many short-lived SYN "probe" flows that each hold
# only 1-2 packets. Such flows have degenerate CICIDS2017 features (zero
# duration, no IAT, no window size), so the flow-level ML model classifies them
# as BENIGN. Rather than fabricate features or run per-packet inference, a
# lightweight aggregator runs inside the existing 5-second flow sampler: it
# groups unestablished SYN probes by source IP and raises ONE PortScan alert
# when a source fans out across many distinct destination ports (vertical scan)
# or many distinct destination hosts (horizontal sweep) within the window.
SCAN_DETECTION_ENABLED = os.getenv("SCAN_DETECTION_ENABLED", "true").lower() == "true"

# Distinct destination ports a single source must probe (SYN, unestablished)
# before it is flagged as a vertical port scan.
SCAN_PORT_FANOUT_THRESHOLD = int(os.getenv("SCAN_PORT_FANOUT_THRESHOLD", "15"))

# Distinct destination hosts a single source must probe on before it is flagged
# as a horizontal sweep.
SCAN_HOST_FANOUT_THRESHOLD = int(os.getenv("SCAN_HOST_FANOUT_THRESHOLD", "15"))

# A flow counts as a "probe" only if it holds at most this many packets. A real
# TCP session completes a 3-way handshake and exceeds this quickly, so normal
# traffic is naturally excluded.
SCAN_MAX_PROBE_PACKETS = int(os.getenv("SCAN_MAX_PROBE_PACKETS", "2"))

# After a source triggers a scan alert, suppress further alerts for it for this
# many seconds so a sustained scan does not spam the dashboard.
SCAN_ALERT_COOLDOWN_SECONDS = float(os.getenv("SCAN_ALERT_COOLDOWN_SECONDS", "30"))

# ---------------------------------------------------------------------------
# Machine learning (Phase 2)
# ---------------------------------------------------------------------------
TEST_SIZE = 0.2          # Fraction of the dataset held back for evaluation.
RANDOM_STATE = 42        # Fixed seed so every training run is reproducible.
N_ESTIMATORS = 100       # Number of trees in the Random Forest.


def ensure_directories() -> None:
    """Create every runtime directory if it does not already exist.

    Git does not track empty folders, so a fresh clone can be missing
    `logs/` or `database/`. Calling this once at startup avoids
    "No such file or directory" crashes later.
    """
    for directory in (DATASET_DIR, MODELS_DIR, DATABASE_DIR, LOGS_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
