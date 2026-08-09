"""
tests/test_detection_engine.py
===============================
Pytest suite for Phase 5 – Detection Engine module.
"""

import time
import pytest
from backend.detection_engine import DetectionEngine


def test_detection_engine_initialization():
    engine = DetectionEngine()
    assert engine.model is not None
    assert engine.extractor is not None
    assert not engine.is_running()


def test_process_single_packet():
    engine = DetectionEngine()

    pkt = {
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp": time.time(),
        "length": 512,
        "header_len": 20,
        "tcp_flags": {"SYN": False, "ACK": True, "PSH": True},
    }

    result = engine.process_packet(pkt)

    assert "prediction" in result
    assert result["prediction"] in ["BENIGN", "ATTACK"]
    assert "confidence_pct" in result
    assert 0.0 <= result["confidence_pct"] <= 100.0
    assert "attack_type" in result
    assert "id" in result


def test_detection_engine_lifecycle():
    engine = DetectionEngine()
    engine.start(mode="simulation")
    assert engine.is_running()

    time.sleep(0.3)
    engine.stop()
    assert not engine.is_running()

    stats = engine.get_live_stats()
    assert stats["total_packets"] > 0
    assert "threat_level" in stats
    assert stats["threat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
