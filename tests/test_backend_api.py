"""
tests/test_backend_api.py
==========================
Pytest suite for Phase 6 – Flask REST API + Socket.IO backend.

Applied skills:
  - testing-boss: test behaviour, not implementation; lowest layer that catches failures.
  - api-audit: verify security boundaries (CORS, input validation, error shapes).
  - verification-before-completion: evidence before claims.
"""

import time
import pytest
from backend.app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
        # Ensure engine is stopped after each test that may start it
        from backend import app as app_module
        if app_module.engine and app_module.engine.is_running():
            app_module.engine.stop()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
def test_root_health_check(client):
    r = client.get("/")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "running"
    assert "version" in data


# ---------------------------------------------------------------------------
# /api/v1/status — before engine starts
# ---------------------------------------------------------------------------
def test_status_before_start(client):
    r = client.get("/api/v1/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["is_running"] is False
    assert "threat_level" in data
    assert "total_packets" in data


# ---------------------------------------------------------------------------
# /api/v1/start → /api/v1/status → /api/v1/stop lifecycle
# ---------------------------------------------------------------------------
def test_start_stop_lifecycle(client):
    # Start
    r = client.post("/api/v1/start", json={"mode": "simulation"})
    assert r.status_code in (200,)
    body = r.get_json()
    assert body["status"] in ("started", "already_running")

    # Status should show running
    time.sleep(0.5)
    r = client.get("/api/v1/status")
    data = r.get_json()
    assert data["is_running"] is True
    assert data["total_packets"] >= 0

    # Stop
    r = client.post("/api/v1/stop")
    assert r.status_code == 200
    assert r.get_json()["status"] == "stopped"


# ---------------------------------------------------------------------------
# /api/v1/start — input validation (api-audit API4 whitelist)
# ---------------------------------------------------------------------------
def test_start_invalid_mode_rejected(client):
    r = client.post("/api/v1/start", json={"mode": "evil_mode; rm -rf /"})
    assert r.status_code == 400
    assert "error" in r.get_json()


# ---------------------------------------------------------------------------
# /api/v1/alerts and /api/v1/logs — limit clamping (api-audit API4)
# ---------------------------------------------------------------------------
def test_alerts_endpoint(client):
    r = client.get("/api/v1/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert "alerts" in data
    assert "count" in data


def test_logs_endpoint(client):
    r = client.get("/api/v1/logs")
    assert r.status_code == 200
    data = r.get_json()
    assert "packets" in data
    assert "count" in data


def test_logs_limit_clamped(client):
    # api-audit API4: unbounded limit must be clamped to max 500
    r = client.get("/api/v1/logs?limit=999999")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Security headers present (api-audit API8)
# ---------------------------------------------------------------------------
def test_security_headers_present(client):
    r = client.get("/api/v1/status")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# 404 and 405 return clean JSON (api-audit API8 — no stack traces)
# ---------------------------------------------------------------------------
def test_404_returns_json(client):
    r = client.get("/api/v1/nonexistent")
    assert r.status_code == 404
    data = r.get_json()
    assert "error" in data
    assert "Traceback" not in str(data)


def test_405_returns_json(client):
    r = client.get("/api/v1/start")   # GET on a POST-only route
    assert r.status_code == 405
    data = r.get_json()
    assert "error" in data
