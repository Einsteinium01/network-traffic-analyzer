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
