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


def test_process_packet_updates_flow_table():
    """
    process_packet is a capture-thread callback: it updates raw counters and the
    flow table and returns None. XGBoost is NOT called here — inference happens
    in the flow-sampler thread. This test pins that contract.
    """
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

    assert result is None  # fast callback, no inference on the capture thread
    assert engine.stats["total_packets"] == 1
    assert engine.stats["total_bytes"] == 512
    assert len(engine.extractor.active_flows) == 1


def test_sampler_predicts_established_flow():
    """
    An established (non-probe) flow with >= 2 packets is classified by XGBoost
    during a sampler cycle, and the result is delivered to alert listeners with
    the standard result-dict shape.
    """
    engine = DetectionEngine()
    results = []
    engine.register_alert_listener(results.append)

    now = time.time()
    # SYN, SYN-ACK, then pushed data — a real session, not a scan probe.
    engine.process_packet({
        "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
        "src_port": 54321, "dst_port": 443, "protocol": "TCP",
        "timestamp": now, "length": 74, "header_len": 40,
        "tcp_flags": {"SYN": True},
    })
    engine.process_packet({
        "src_ip": "8.8.8.8", "dst_ip": "192.168.1.50",
        "src_port": 443, "dst_port": 54321, "protocol": "TCP",
        "timestamp": now + 0.01, "length": 74, "header_len": 40,
        "tcp_flags": {"SYN": True, "ACK": True},
    })
    engine.process_packet({
        "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
        "src_port": 54321, "dst_port": 443, "protocol": "TCP",
        "timestamp": now + 0.02, "length": 512, "header_len": 32,
        "tcp_flags": {"ACK": True, "PSH": True},
    })

    engine._sample_and_predict_flows()

    assert len(results) == 1
    result = results[0]
    assert result["prediction"] in ["BENIGN", "ATTACK"]
    assert 0.0 <= result["confidence_pct"] <= 100.0
    assert result["detector"] == "xgboost"
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
