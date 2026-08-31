"""
tests/test_feature_extraction.py
=================================
Pytest suite for Phase 4 – Feature Extraction module.
"""

import pathlib
import pytest
import pandas as pd
from feature_extraction import Flow, FeatureExtractor

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_flow_initialization_and_packet_addition():
    pkt1 = {
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp": 100.0,
        "length": 64,
        "header_len": 20,
        "tcp_flags": {"SYN": True, "ACK": False},
    }

    flow = Flow(pkt1)
    assert flow.fwd_pkts == 1
    assert flow.bwd_pkts == 0
    assert flow.src_port == 54321
    assert flow.dst_port == 443

    # Add backward packet
    pkt2 = {
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.10",
        "src_port": 443,
        "dst_port": 54321,
        "protocol": "TCP",
        "timestamp": 100.05,  # 50ms later
        "length": 128,
        "header_len": 20,
        "tcp_flags": {"SYN": True, "ACK": True},
    }

    flow.add_packet(pkt2)
    assert flow.fwd_pkts == 1
    assert flow.bwd_pkts == 1

    features = flow.to_feature_dict()
    assert isinstance(features, dict)
    assert features["Destination Port"] == 443.0
    assert features["Total Fwd Packets"] == 1.0
    assert features["Total Backward Packets"] == 1.0
    assert features["Flow Duration"] == pytest.approx(50000.0)  # 50ms = 50,000 us


# ---------------------------------------------------------------------------
# Feature-parity correctness fixes (CICFlowMeter semantics).
# Each test below pins one of the five corrected areas against the behaviour
# observed in the CICIDS2017 training data.
# ---------------------------------------------------------------------------

def _tcp_pkt(src_ip, sp, dst_ip, dp, ts, *, payload_len, hdr_len=20,
             init_win=8192, flags=None, length=None):
    """Build an npcap-style TCP packet dict (payload_len + init_win supplied)."""
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": sp, "dst_port": dp,
        "protocol": "TCP", "timestamp": ts,
        "length": length if length is not None else payload_len + hdr_len + 14,
        "payload_len": payload_len,
        "header_len": hdr_len,
        "init_win": init_win,
        "tcp_flags": flags or {"ACK": True},
    }


# ── #1 Flow IAT initialization bug ───────────────────────────────────────────
def test_flow_iat_not_recorded_on_first_packet():
    """First packet has no predecessor, so it must not record a 0 flow IAT."""
    p1 = _tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                  payload_len=0, flags={"SYN": True})
    flow = Flow(p1)
    # No IAT observation exists yet — not a spurious zero.
    assert flow.flow_iat_stats.n == 0
    f = flow.to_feature_dict()
    assert f["Flow IAT Mean"] == 0.0
    assert f["Flow IAT Max"] == 0.0
    assert f["Flow IAT Min"] == 0.0

    # Second packet 50 ms later → exactly one IAT of 50,000 µs (no 0 dragging it down).
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.05,
                             payload_len=100, flags={"ACK": True}))
    assert flow.flow_iat_stats.n == 1
    f = flow.to_feature_dict()
    assert f["Flow IAT Mean"] == pytest.approx(50000.0)
    assert f["Flow IAT Min"] == pytest.approx(50000.0)  # would be 0 with the old bug


# ── #2 Init_Win_bytes_forward / _backward ────────────────────────────────────
def test_init_win_populated_from_first_packet_each_direction():
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                         payload_len=0, init_win=8192, flags={"SYN": True}))
    # First backward packet carries the server's window.
    flow.add_packet(_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 5000, 100.01,
                             payload_len=0, init_win=64240, flags={"SYN": True, "ACK": True}))
    # A later forward packet must NOT overwrite the initial forward window.
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.02,
                             payload_len=100, init_win=502, flags={"ACK": True}))
    f = flow.to_feature_dict()
    assert f["Init_Win_bytes_forward"] == 8192.0
    assert f["Init_Win_bytes_backward"] == 64240.0


def test_init_win_zero_window_is_kept_not_sentinel():
    """A genuine TCP zero-window (0) must be recorded, not read as 'no window'."""
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                         payload_len=0, init_win=0, flags={"SYN": True}))
    assert flow.to_feature_dict()["Init_Win_bytes_forward"] == 0.0


def test_init_win_sentinel_for_non_tcp():
    """Non-TCP flows never observe a TCP window → -1 sentinel in both directions."""
    udp = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": 5000, "dst_port": 53, "protocol": "UDP",
        "timestamp": 100.0, "length": 80, "payload_len": 52, "header_len": 8,
    }
    f = Flow(udp).to_feature_dict()
    assert f["Init_Win_bytes_forward"] == -1.0
    assert f["Init_Win_bytes_backward"] == -1.0


# ── #3 min_seg_size_forward ──────────────────────────────────────────────────
def test_min_seg_size_forward_tracks_minimum_header():
    """Not the hard-coded 32 — the minimum forward L4 header length seen."""
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                         payload_len=0, hdr_len=32, flags={"SYN": True}))  # SYN + options
    assert flow.to_feature_dict()["min_seg_size_forward"] == 32.0
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.02,
                             payload_len=100, hdr_len=20, flags={"ACK": True}))  # bare ACK
    assert flow.to_feature_dict()["min_seg_size_forward"] == 20.0


# ── #4 payload-based packet length statistics ────────────────────────────────
def test_packet_length_stats_use_l4_payload():
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                         payload_len=0, flags={"SYN": True}))          # control → 0
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.01,
                             payload_len=100))                          # fwd data
    flow.add_packet(_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 5000, 100.02,
                             payload_len=200))                          # bwd data
    f = flow.to_feature_dict()
    assert f["Total Length of Fwd Packets"] == 100.0        # 0 + 100
    assert f["Total Length of Bwd Packets"] == 200.0
    assert f["Fwd Packet Length Max"] == 100.0
    assert f["Fwd Packet Length Min"] == 0.0                # the SYN contributes 0
    assert f["Min Packet Length"] == 0.0
    assert f["Max Packet Length"] == 200.0
    # Segment-size aliases equal the corresponding payload means.
    assert f["Avg Fwd Segment Size"] == pytest.approx(f["Fwd Packet Length Mean"])
    assert f["Avg Bwd Segment Size"] == pytest.approx(f["Bwd Packet Length Mean"])


def test_act_data_pkt_fwd_counts_only_payload_packets():
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0,
                         payload_len=0, flags={"SYN": True}))          # no payload
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.01,
                             payload_len=0, flags={"ACK": True}))       # bare ACK, no payload
    flow.add_packet(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.02,
                             payload_len=512, flags={"PSH": True, "ACK": True}))  # data
    assert flow.to_feature_dict()["act_data_pkt_fwd"] == 1.0


def test_average_packet_size_is_mean_times_n_plus_1_over_n():
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0, payload_len=100))
    flow.add_packet(_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 5000, 100.01, payload_len=200))
    f = flow.to_feature_dict()
    n, mean = 2.0, 150.0                                   # payloads 100, 200
    assert f["Packet Length Mean"] == pytest.approx(mean)
    assert f["Average Packet Size"] == pytest.approx(mean * (n + 1) / n)  # 225.0


# ── #5 short-flow rate handling ──────────────────────────────────────────────
def test_rates_use_real_duration_without_one_second_floor():
    """1 ms flow → rate over 0.001 s, NOT clamped to a 1-second window."""
    flow = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.000, payload_len=1000))
    flow.add_packet(_tcp_pkt("10.0.0.2", 80, "10.0.0.1", 5000, 100.001, payload_len=1000))
    f = flow.to_feature_dict()
    assert f["Flow Duration"] == pytest.approx(1000.0)              # 1 ms in µs
    assert f["Flow Packets/s"] == pytest.approx(2000.0)            # 2 / 0.001
    assert f["Flow Bytes/s"] == pytest.approx(2_000_000.0)         # 2000 / 0.001


def test_zero_duration_flow_is_finite_and_capped():
    """Zero-duration flows (CICFlowMeter → +Inf, dropped from training) stay finite."""
    import math
    huge = Flow(_tcp_pkt("10.0.0.1", 5000, "10.0.0.2", 80, 100.0, payload_len=100_000))
    f = huge.to_feature_dict()
    assert math.isfinite(f["Flow Bytes/s"]) and math.isfinite(f["Flow Packets/s"])
    assert f["Flow Bytes/s"] <= 2.1e9        # capped at the training envelope
    assert f["Flow Packets/s"] <= 4.0e6



def test_feature_extractor_dataframe_alignment():
    extractor = FeatureExtractor(feature_cols_path=ROOT / "models" / "feature_columns.pkl")
    assert len(extractor.expected_features) == 70

    pkt = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "timestamp": 200.0,
        "length": 100,
        "header_len": 20,
    }

    df = extractor.extract_features(pkt)
    assert isinstance(df, pd.DataFrame)
    assert df.shape == (1, 70)
    assert list(df.columns) == extractor.expected_features
    assert not df.isna().any().any()
