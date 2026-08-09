"""
backend/app.py
==============
WHY THIS FILE EXISTS
--------------------
Phase 6: Flask REST API + Flask-SocketIO real-time backend.

This is the central web server that:
  1. Exposes REST endpoints consumed by the React dashboard (Phase 7).
  2. Streams live packet and alert events over WebSockets using Socket.IO.
  3. Owns the singleton DetectionEngine and controls its lifecycle.

SECURITY (api-audit doctrine applied)
--------------------------------------
API8 – Security Misconfiguration:
  - CORS restricted to known dev/prod origins; no wildcard + credentials.
  - Stack traces never leak into JSON error responses.
  - Security headers added on every response (X-Content-Type-Options, etc.).

API4 – Unrestricted Resource Consumption:
  - All list endpoints accept a bounded 'limit' param (max 500).

API3 – Excessive Data Exposure:
  - Every endpoint returns only the fields the client needs.

API9 – Inventory Management:
  - A single versioned prefix (/api/v1) keeps the surface explicit.

HOW IT WORKS
------------
- Flask app is created with a factory function `create_app()` so it can be
  imported cleanly in tests or WSGI servers.
- Flask-SocketIO runs the event loop in threading mode (no eventlet/gevent
  dependency required on Windows).
- DetectionEngine is started/stopped via /api/v1/start and /api/v1/stop.
- Every captured packet fires a 'packet' SocketIO event; attacks also fire
  an 'alert' event — the React frontend subscribes to both.

FILE: backend/app.py
RUN:  python backend/app.py
"""

import sys
import pathlib
import logging
import time
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, request, Response
from flask_socketio import SocketIO
from flask_cors import CORS

# Add project root to sys.path so sibling packages import cleanly
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detection_engine import DetectionEngine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_PATH = ROOT / "logs" / "app.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_sh = logging.StreamHandler(sys.stdout)
if hasattr(_sh.stream, "reconfigure"):
    _sh.stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        _sh,
        logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger("backend.app")

# ---------------------------------------------------------------------------
# Allowed CORS origins (localhost dev + localhost production build)
# api-audit API8: never wildcard + credentials
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    "http://localhost:5173",   # Vite dev server
    "http://localhost:4173",   # Vite preview
    "http://localhost:3000",   # CRA / alternative dev
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# ---------------------------------------------------------------------------
# Singleton detection engine (shared across requests + SocketIO events)
# ---------------------------------------------------------------------------
engine: DetectionEngine = None   # type: ignore[assignment]
socketio: SocketIO = None        # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    global engine, socketio

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "nta-dev-secret-not-for-production"
    app.config["JSON_SORT_KEYS"] = False

    # --- CORS (api-audit API8) -------------------------------------------
    CORS(
        app,
        resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
        supports_credentials=False,
    )

    # --- SocketIO -----------------------------------------------------------
    socketio = SocketIO(
        app,
        cors_allowed_origins=ALLOWED_ORIGINS,
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # --- DetectionEngine ----------------------------------------------------
    engine = DetectionEngine()

    # Register listener: broadcast every processed packet over WebSocket
    def _broadcast_packet(result: Dict[str, Any]) -> None:
        """Push packet/alert events to all connected Socket.IO clients."""
        if socketio and not app.config.get("TESTING"):
            try:
                socketio.emit("packet", result)
                if result.get("is_attack"):
                    socketio.emit("alert", result)
            except Exception as err:
                log.debug("SocketIO emit exception: %s", err)

    engine.register_alert_listener(_broadcast_packet)

    # --- Security headers on every response (api-audit API8) ---------------
    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    # ========================================================================
    # REST ENDPOINTS
    # ========================================================================

    # ── GET / ──────────────────────────────────────────────────────────────
    @app.get("/")
    def dashboard() -> Response:
        """Health-check / dashboard entry-point."""
        return jsonify({
            "service": "Intelligent Network Traffic Analyzer",
            "version": "1.0.0",
            "status": "running",
            "docs": "/api/v1",
        })

    # ── POST /api/v1/start ─────────────────────────────────────────────────
    @app.post("/api/v1/start")
    def start_monitoring() -> Response:
        """
        Start real-time packet capture and ML-based intrusion detection.

        JSON body (optional):
          { "mode": "simulation" | "auto" | "scapy" | "raw_socket" }
        """
        body = request.get_json(silent=True) or {}
        mode = str(body.get("mode", "auto"))

        # api-audit API4: whitelist accepted values, never trust raw user input
        allowed_modes = {"auto", "simulation", "scapy", "raw_socket"}
        if mode not in allowed_modes:
            return jsonify({"error": f"Invalid mode '{mode}'. Choose from: {sorted(allowed_modes)}"}), 400

        if engine.is_running():
            return jsonify({"status": "already_running", "message": "Engine is already running."}), 200

        try:
            engine.start(mode=mode)
            log.info("DetectionEngine started via REST (mode=%s).", mode)
            return jsonify({"status": "started", "mode": engine.sniffer.active_mode}), 200
        except Exception as exc:
            log.error("Failed to start engine: %s", exc)
            return jsonify({"error": "Failed to start monitoring engine."}), 500

    # ── POST /api/v1/stop ──────────────────────────────────────────────────
    @app.post("/api/v1/stop")
    def stop_monitoring() -> Response:
        """Stop packet capture and intrusion detection."""
        if not engine.is_running():
            return jsonify({"status": "already_stopped", "message": "Engine is not running."}), 200
        try:
            engine.stop()
            log.info("DetectionEngine stopped via REST.")
            return jsonify({"status": "stopped"}), 200
        except Exception as exc:
            log.error("Failed to stop engine: %s", exc)
            return jsonify({"error": "Failed to stop monitoring engine."}), 500

    # ── GET /api/v1/status ─────────────────────────────────────────────────
    @app.get("/api/v1/status")
    def live_status() -> Response:
        """
        Return live traffic statistics and threat level.

        api-audit API3: returns a curated DTO, not the full engine state.
        """
        stats = engine.get_live_stats()
        return jsonify({
            "is_running": stats["is_running"],
            "mode": stats["mode"],
            "threat_level": stats["threat_level"],
            "total_packets": stats["total_packets"],
            "normal_packets": stats["normal_packets"],
            "attack_packets": stats["attack_packets"],
            "normal_pct": stats["normal_pct"],
            "attack_pct": stats["attack_pct"],
            "packets_per_second": stats["packets_per_second"],
            "bytes_per_second": stats["bytes_per_second"],
            "duration_seconds": stats["duration_seconds"],
        }), 200

    # ── GET /api/v1/alerts ─────────────────────────────────────────────────
    @app.get("/api/v1/alerts")
    def get_alerts() -> Response:
        """
        Return history of detected intrusion alerts.

        Query params:
          limit (int, 1-500, default 50)
        """
        limit = _parse_limit(request.args.get("limit", 50), max_val=500)
        alerts = engine.get_alerts(limit=limit)
        return jsonify({
            "count": len(alerts),
            "alerts": alerts,
        }), 200

    # ── GET /api/v1/logs ───────────────────────────────────────────────────
    @app.get("/api/v1/logs")
    def get_logs() -> Response:
        """
        Return history of all recently processed packets (both normal + attack).

        Query params:
          limit (int, 1-500, default 50)
        """
        limit = _parse_limit(request.args.get("limit", 50), max_val=500)
        packets = engine.get_recent_packets(limit=limit)
        return jsonify({
            "count": len(packets),
            "packets": packets,
        }), 200

    # ── Error handlers ──────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(_err: Any) -> Response:
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_err: Any) -> Response:
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(_err: Any) -> Response:
        # api-audit API8: never leak stack traces
        log.exception("Unhandled internal error.")
        return jsonify({"error": "Internal server error."}), 500

    # ========================================================================
    # SOCKET.IO EVENTS
    # ========================================================================

    @socketio.on("connect")
    def on_connect() -> None:
        log.info("Socket.IO client connected: %s", request.sid)
        # Send current status snapshot on connect
        socketio.emit("status", engine.get_live_stats(), to=request.sid)

    @socketio.on("disconnect")
    def on_disconnect() -> None:
        log.info("Socket.IO client disconnected: %s", request.sid)

    @socketio.on("request_status")
    def on_request_status() -> None:
        socketio.emit("status", engine.get_live_stats(), to=request.sid)

    log.info("Flask app created. Routes: GET / | POST /api/v1/start | POST /api/v1/stop "
             "| GET /api/v1/status | GET /api/v1/alerts | GET /api/v1/logs")

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_limit(raw: Any, max_val: int = 500) -> int:
    """Parse and clamp a 'limit' query parameter (api-audit API4)."""
    try:
        val = int(raw)
        return max(1, min(val, max_val))
    except (TypeError, ValueError):
        return 50


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    log.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
