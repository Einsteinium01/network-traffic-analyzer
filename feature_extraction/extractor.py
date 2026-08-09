"""
feature_extraction/extractor.py
================================
WHY THIS FILE EXISTS
--------------------
Provides `FeatureExtractor`, the pipeline component that converts raw live packets
or active network flow tables into structured 2D feature arrays / DataFrames
ready for Machine Learning inference.

HOW IT WORKS
------------
1. Maintains a table of active bidirectional flows `(Src IP, Src Port, Dst IP, Dst Port, Protocol)`.
2. As each packet is ingested via `process_packet(pkt)`, it updates the corresponding flow.
3. Automatically computes instantaneous feature vectors or flushes expired/completed flows.
4. Ensures all feature column names, data types, and column ordering match `models/feature_columns.pkl`.

FILE: feature_extraction/extractor.py
"""

import time
import pathlib
import logging
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
import joblib

from feature_extraction.flow import Flow

logger = logging.getLogger(__name__)

# Default path to trained feature columns
ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_FEATURE_COLS_PATH = ROOT / "models" / "feature_columns.pkl"


class FeatureExtractor:
    """
    Manages active flows and extracts ML-ready feature DataFrames.
    """

    def __init__(
        self,
        feature_cols_path: Optional[pathlib.Path] = None,
        idle_timeout: float = 15.0,
        max_flow_duration: float = 120.0,
    ):
        """
        Initialize FeatureExtractor.

        :param feature_cols_path: Path to feature_columns.pkl (loads standard 70 columns)
        :param idle_timeout: Idle time in seconds after which a flow is considered completed
        :param max_flow_duration: Maximum duration in seconds for an active flow
        """
        self.feature_cols_path = feature_cols_path or DEFAULT_FEATURE_COLS_PATH
        self.idle_timeout = idle_timeout
        self.max_flow_duration = max_flow_duration

        # Load expected feature columns from file or use fallback list
        self.expected_features: List[str] = self._load_feature_columns()

        # Active Flow Table: maps 5-tuple -> Flow instance
        self.active_flows: Dict[Tuple[str, int, str, int, str], Flow] = {}

    def _load_feature_columns(self) -> List[str]:
        """Load expected feature column list from pkl file."""
        if self.feature_cols_path.exists():
            try:
                cols = joblib.load(self.feature_cols_path)
                logger.info(f"Loaded {len(cols)} feature columns from {self.feature_cols_path.name}")
                return list(cols)
            except Exception as e:
                logger.warning(f"Error loading feature_columns.pkl ({e}). Using default schema.")
        else:
            logger.warning(f"feature_columns.pkl not found at {self.feature_cols_path}. Using fallback.")

        # Fallback to standard 70 CICIDS2017 feature column names
        return [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
            'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
            'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
            'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]

    def _get_flow_key(self, pkt: Dict[str, Any]) -> Tuple[Tuple[str, int, str, int, str], bool]:
        """
        Return the canonical 5-tuple key for the packet and direction flag.
        """
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        src_port = pkt.get("src_port", 0)
        dst_port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "OTHER")

        fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)

        if fwd_key in self.active_flows:
            return fwd_key, True
        elif bwd_key in self.active_flows:
            return bwd_key, False
        else:
            return fwd_key, True

    def process_packet(self, pkt: Dict[str, Any]) -> Tuple[Flow, Dict[str, Any]]:
        """
        Ingest a packet into active flow table and return updated Flow & feature dict.
        """
        flow_key, is_fwd = self._get_flow_key(pkt)

        if flow_key not in self.active_flows:
            flow = Flow(pkt)
            self.active_flows[flow_key] = flow
        else:
            flow = self.active_flows[flow_key]
            flow.add_packet(pkt)

        feature_dict = flow.to_feature_dict()
        return flow, feature_dict

    def extract_features(self, packet_or_flow) -> pd.DataFrame:
        """
        Convert a packet dictionary or Flow instance into a 1-row DataFrame aligned
        with expected 70 ML feature columns.
        """
        if isinstance(packet_or_flow, Flow):
            feat_dict = packet_or_flow.to_feature_dict()
        elif isinstance(packet_or_flow, dict):
            if "Destination Port" in packet_or_flow:  # Already a feature dict
                feat_dict = packet_or_flow
            else:  # Raw packet dict
                _, feat_dict = self.process_packet(packet_or_flow)
        else:
            raise ValueError(f"Unsupported input type for feature extraction: {type(packet_or_flow)}")

        # Construct DataFrame and align columns strictly
        df = pd.DataFrame([feat_dict])

        # Fill missing columns with 0.0 and reorder to match training schema
        for col in self.expected_features:
            if col not in df.columns:
                df[col] = 0.0

        # Ensure correct column order
        df_aligned = df[self.expected_features].astype(float)
        return df_aligned

    def flush_expired_flows(self, current_time: Optional[float] = None) -> List[Tuple[Flow, Dict[str, Any]]]:
        """
        Remove and return flows that have timed out or exceeded max duration.
        """
        now = current_time or time.time()
        expired = []
        keys_to_remove = []

        for key, flow in self.active_flows.items():
            idle_duration = now - flow.last_seen
            total_duration = now - flow.start_time

            if idle_duration >= self.idle_timeout or total_duration >= self.max_flow_duration:
                keys_to_remove.append(key)
                expired.append((flow, flow.to_feature_dict()))

        for key in keys_to_remove:
            del self.active_flows[key]

        return expired

    def clear(self) -> None:
        """Clear all active flows."""
        self.active_flows.clear()
