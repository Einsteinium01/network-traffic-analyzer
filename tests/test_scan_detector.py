"""
tests/test_scan_detector.py
===========================
Unit tests for the heuristic PortScan aggregation layer (ScanDetector).

These tests are PURE: they exercise ScanDetector against synthetic Flow objects
only. No ML model, no live sniffer, no threads. They prove the two behaviours
that matter for the detection gap this layer was built to close:

  * a rapid single-packet SYN scan IS detected (the thing the >=2 packet rule
    was silently dropping), and
  * ordinary traffic — established sessions and a slow handful of connections —
    is NOT flagged (no new false positives).
"""

import pytest

from feature_extraction import Flow, ScanDetector


# ── Flow factories ──────────────────────────────────────────────────────────
def make_syn_probe(dst_port, dst_ip="10.0.0.1", src_ip="10.0.0.9", t=1000.0):
    """A lone unestablished SYN — exactly what nmap -sS emits per port."""
    return Flow({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 40000 + (dst_port % 2000),
        "dst_port": dst_port,
        "protocol": "TCP",
        "timestamp": t,
        "length": 60,
        "header_len": 40,          # bare SYN: frame is almost all header, no payload
        "tcp_flags": {"SYN": True},
    })


def make_established_session(dst_port, dst_ip="10.0.0.1", src_ip="10.0.0.9", t=1000.0):
    """
    A normal completed TCP session: SYN out, SYN-ACK back, then a PSH data
    packet. Four packets total with PSH set — must never look like a probe.
    """
    src_port = 50000 + (dst_port % 2000)
    flow = Flow({
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": "TCP", "timestamp": t,
        "length": 74, "header_len": 40,
        "tcp_flags": {"SYN": True},
    })
    # SYN-ACK back
    flow.add_packet({
        "src_ip": dst_ip, "dst_ip": src_ip,
        "src_port": dst_port, "dst_port": src_port,
        "protocol": "TCP", "timestamp": t + 0.01,
        "length": 74, "header_len": 40,
        "tcp_flags": {"SYN": True, "ACK": True},
    })
    # ACK + pushed data forward
    flow.add_packet({
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": "TCP", "timestamp": t + 0.02,
        "length": 517, "header_len": 32,
        "tcp_flags": {"ACK": True, "PSH": True},
    })
    # Data back
    flow.add_packet({
        "src_ip": dst_ip, "dst_ip": src_ip,
        "src_port": dst_port, "dst_port": src_port,
        "protocol": "TCP", "timestamp": t + 0.05,
        "length": 1400, "header_len": 32,
        "tcp_flags": {"ACK": True, "PSH": True},
    })
    return flow


# ── is_probe classification ───────────────────────────────────────────────────
def test_lone_syn_is_a_probe():
    det = ScanDetector()
    assert det.is_probe(make_syn_probe(22)) is True


def test_established_session_is_not_a_probe():
    det = ScanDetector()
    flow = make_established_session(443)
    assert flow.fwd_pkts + flow.bwd_pkts > det.max_probe_packets
    assert det.is_probe(flow) is False


def test_udp_flow_is_never_a_probe():
    det = ScanDetector()
    udp = Flow({
        "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1",
        "src_port": 5353, "dst_port": 53,
        "protocol": "UDP", "timestamp": 1000.0,
        "length": 80, "header_len": 8,
    })
    assert det.is_probe(udp) is False


def test_syn_then_fin_is_not_a_probe():
    """A graceful teardown (FIN) means a real connection, not a probe."""
    det = ScanDetector()
    flow = make_syn_probe(80)
    flow.add_packet({
        "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1",
        "src_port": flow.src_port, "dst_port": 80,
        "protocol": "TCP", "timestamp": 1000.1,
        "length": 60, "header_len": 40,
        "tcp_flags": {"FIN": True, "ACK": True},
    })
    assert det.is_probe(flow) is False


# ── Vertical scan (many ports, one host) ──────────────────────────────────────
def test_vertical_portscan_is_detected():
    """20 single-SYN probes to 20 ports on one host → one PortScan alert."""
    det = ScanDetector(port_fanout_threshold=15)
    flows = [make_syn_probe(p) for p in range(20, 40)]

    detections = det.evaluate(flows, now=1000.0)

    assert len(detections) == 1
    d = detections[0]
    assert d["src_ip"] == "10.0.0.9"
    assert d["distinct_ports"] == 20
    assert d["scan_type"] == "vertical"
    assert "PortScan" in d["attack_type"]
    assert 0.85 <= d["confidence"] <= 0.99
    assert d["probe_count"] == 20


def test_just_below_threshold_is_not_detected():
    """14 ports with a threshold of 15 stays quiet — no false positive."""
    det = ScanDetector(port_fanout_threshold=15)
    flows = [make_syn_probe(p) for p in range(20, 34)]  # 14 ports
    assert det.evaluate(flows, now=1000.0) == []


def test_small_port_trickle_is_not_detected():
    """A browser opening 3 connections must never trip the scan detector."""
    det = ScanDetector(port_fanout_threshold=15)
    flows = [make_syn_probe(p) for p in (80, 443, 8080)]
    assert det.evaluate(flows, now=1000.0) == []


# ── Horizontal sweep (one port, many hosts) ───────────────────────────────────
def test_horizontal_sweep_is_detected():
    """One source hitting port 445 across 20 hosts → horizontal sweep."""
    det = ScanDetector(host_fanout_threshold=15)
    flows = [make_syn_probe(445, dst_ip=f"10.0.0.{h}") for h in range(1, 21)]

    detections = det.evaluate(flows, now=1000.0)

    assert len(detections) == 1
    d = detections[0]
    assert d["distinct_hosts"] == 20
    assert d["scan_type"] == "horizontal"


# ── Established traffic never triggers ─────────────────────────────────────────
def test_many_established_sessions_are_not_flagged():
    """30 real HTTPS sessions to 30 ports are NOT a scan (they carry data)."""
    det = ScanDetector(port_fanout_threshold=15)
    flows = [make_established_session(p) for p in range(20, 50)]
    assert det.evaluate(flows, now=1000.0) == []


# ── Cooldown suppression ──────────────────────────────────────────────────────
def test_cooldown_suppresses_repeat_alerts():
    """A sustained scan alerts once, then stays silent during the cooldown."""
    det = ScanDetector(port_fanout_threshold=15, cooldown_seconds=30.0)
    flows = [make_syn_probe(p) for p in range(20, 40)]

    first = det.evaluate(flows, now=1000.0)
    assert len(first) == 1

    # Same scan still visible 5s later — inside cooldown, so no repeat alert.
    second = det.evaluate(flows, now=1005.0)
    assert second == []

    # After the cooldown elapses, an ongoing scan alerts again.
    third = det.evaluate(flows, now=1031.0)
    assert len(third) == 1


def test_reset_clears_cooldown():
    det = ScanDetector(port_fanout_threshold=15, cooldown_seconds=30.0)
    flows = [make_syn_probe(p) for p in range(20, 40)]
    assert len(det.evaluate(flows, now=1000.0)) == 1

    det.reset()  # e.g. monitoring restarted
    # Immediately after reset the same scan is treated as brand new.
    assert len(det.evaluate(flows, now=1001.0)) == 1


# ── Two simultaneous scanners are reported independently ──────────────────────
def test_two_sources_scanning_are_reported_separately():
    det = ScanDetector(port_fanout_threshold=15)
    a = [make_syn_probe(p, src_ip="10.0.0.9") for p in range(20, 40)]
    b = [make_syn_probe(p, src_ip="10.0.0.8") for p in range(20, 40)]

    detections = det.evaluate(a + b, now=1000.0)

    assert len(detections) == 2
    assert {d["src_ip"] for d in detections} == {"10.0.0.9", "10.0.0.8"}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
