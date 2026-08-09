"""
feature_extraction/flow.py
==========================
WHY THIS FILE EXISTS
--------------------
Defines the `Flow` class, which tracks state, directionality (Forward vs Backward),
timing, packet lengths, inter-arrival times (IAT), TCP flags, and subflow metrics
for a 5-tuple network conversation: (Src IP, Src Port, Dst IP, Dst Port, Protocol).

HOW IT WORKS
------------
1. When a packet arrives, `Flow.add_packet()` determines if it is in the Forward
   (Src -> Dst) or Backward (Dst -> Src) direction.
2. Updates packet counts, byte totals, min/max/sum/sqsum for lengths and IATs.
3. Accumulates TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWE).
4. `to_feature_dict()` computes statistical metrics (mean, std, rates, idle/active times)
   and outputs a dictionary with exact column keys matching CICIDS2017 training features.

FILE: feature_extraction/flow.py
"""

import math
import time
from typing import Dict, Any, List, Tuple, Optional


class Flow:
    """
    Tracks state and calculates 70 statistical features for a single 5-tuple flow.
    """

    def __init__(self, first_pkt: Dict[str, Any]):
        """Initialize flow with the first packet."""
        self.src_ip: str = first_pkt["src_ip"]
        self.dst_ip: str = first_pkt["dst_ip"]
        self.src_port: int = first_pkt.get("src_port", 0)
        self.dst_port: int = first_pkt.get("dst_port", 0)
        self.protocol: str = first_pkt.get("protocol", "OTHER")

        # Forward direction is defined by the first packet's direction
        self.fwd_key = (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
        self.bwd_key = (self.dst_ip, self.dst_port, self.src_ip, self.src_port, self.protocol)

        # Timestamps (seconds as float)
        ts = first_pkt.get("timestamp", time.time())
        self.start_time: float = ts
        self.last_seen: float = ts
        self.fwd_last_seen: Optional[float] = None
        self.bwd_last_seen: Optional[float] = None

        # Packet Counts
        self.fwd_pkts: int = 0
        self.bwd_pkts: int = 0

        # Packet Lengths
        self.fwd_pkt_lengths: List[int] = []
        self.bwd_pkt_lengths: List[int] = []
        self.all_pkt_lengths: List[int] = []

        # Inter-Arrival Times (in microseconds as floats, matching CICIDS2017)
        self.flow_iats: List[float] = []
        self.fwd_iats: List[float] = []
        self.bwd_iats: List[float] = []

        # Header Lengths
        self.fwd_header_len: int = 0
        self.bwd_header_len: int = 0

        # TCP Flags
        self.flag_counts = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "ECE": 0, "CWE": 0,
            "fwd_psh": 0, "fwd_urg": 0,
        }

        # Active & Idle Times (microseconds)
        self.active_times: List[float] = []
        self.idle_times: List[float] = []
        self.current_active_start: float = ts
        self.idle_threshold: float = 1.0  # 1 second threshold for idle gap

        # Window sizes & seg sizes
        self.init_win_fwd: int = 0
        self.init_win_bwd: int = 0
        self.act_data_pkt_fwd: int = 0
        self.min_seg_size_fwd: int = 32

        # Add the initial packet
        self.add_packet(first_pkt)

    def is_forward(self, pkt: Dict[str, Any]) -> bool:
        """Check if packet is in the forward direction."""
        return (
            pkt["src_ip"] == self.src_ip
            and pkt.get("src_port", 0) == self.src_port
            and pkt["dst_ip"] == self.dst_ip
            and pkt.get("dst_port", 0) == self.dst_port
        )

    def add_packet(self, pkt: Dict[str, Any]) -> None:
        """Process and incorporate a new packet into the flow."""
        ts = pkt.get("timestamp", time.time())
        length = pkt.get("length", 60)
        hdr_len = pkt.get("header_len", 20)

        # Flow-level IAT (microseconds)
        if self.last_seen > 0:
            flow_iat = (ts - self.last_seen) * 1e6
            if flow_iat >= 0:
                self.flow_iats.append(flow_iat)

                # Active / Idle tracking
                gap_sec = ts - self.last_seen
                if gap_sec > self.idle_threshold:
                    idle_us = gap_sec * 1e6
                    self.idle_times.append(idle_us)
                    active_us = (self.last_seen - self.current_active_start) * 1e6
                    if active_us > 0:
                        self.active_times.append(active_us)
                    self.current_active_start = ts

        self.last_seen = max(self.last_seen, ts)
        self.all_pkt_lengths.append(length)

        is_fwd = self.is_forward(pkt)

        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_pkt_lengths.append(length)
            self.fwd_header_len += hdr_len

            if self.fwd_last_seen is not None:
                fwd_iat = (ts - self.fwd_last_seen) * 1e6
                if fwd_iat >= 0:
                    self.fwd_iats.append(fwd_iat)
            self.fwd_last_seen = ts

            # Payload packet counter
            payload_len = max(0, length - hdr_len)
            if payload_len > 0:
                self.act_data_pkt_fwd += 1

        else:  # Backward direction
            self.bwd_pkts += 1
            self.bwd_pkt_lengths.append(length)
            self.bwd_header_len += hdr_len

            if self.bwd_last_seen is not None:
                bwd_iat = (ts - self.bwd_last_seen) * 1e6
                if bwd_iat >= 0:
                    self.bwd_iats.append(bwd_iat)
            self.bwd_last_seen = ts

        # Flags
        flags = pkt.get("tcp_flags")
        if flags and isinstance(flags, dict):
            for flag_name in ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWE"]:
                if flags.get(flag_name):
                    self.flag_counts[flag_name] += 1
                    if is_fwd and flag_name == "PSH":
                        self.flag_counts["fwd_psh"] += 1
                    if is_fwd and flag_name == "URG":
                        self.flag_counts["fwd_urg"] += 1

    # -------------------------------------------------------------------------
    # Helper Statistical Calculations
    # -------------------------------------------------------------------------
    @staticmethod
    def _stats(arr: List[float]) -> Tuple[float, float, float, float, float]:
        """Return (min, max, mean, std, variance) for a list of numbers."""
        if not arr:
            return 0.0, 0.0, 0.0, 0.0, 0.0
        n = len(arr)
        mn = float(min(arr))
        mx = float(max(arr))
        mean = float(sum(arr) / n)
        if n > 1:
            var = float(sum((x - mean) ** 2 for x in arr) / (n - 1))
            std = float(math.sqrt(var))
        else:
            var = 0.0
            std = 0.0
        return mn, mx, mean, std, var

    def to_feature_dict(self) -> Dict[str, float]:
        """
        Calculates all 70 CICIDS2017 features expected by the trained ML model.
        """
        duration_us = max(0.0, (self.last_seen - self.start_time) * 1e6)
        duration_sec = max(duration_us / 1e6, 0.000001)

        fwd_len_min, fwd_len_max, fwd_len_mean, fwd_len_std, _ = self._stats(self.fwd_pkt_lengths)
        bwd_len_min, bwd_len_max, bwd_len_mean, bwd_len_std, _ = self._stats(self.bwd_pkt_lengths)
        all_len_min, all_len_max, all_len_mean, all_len_std, all_len_var = self._stats(self.all_pkt_lengths)

        tot_fwd_bytes = float(sum(self.fwd_pkt_lengths))
        tot_bwd_bytes = float(sum(self.bwd_pkt_lengths))
        tot_bytes = tot_fwd_bytes + tot_bwd_bytes
        tot_pkts = self.fwd_pkts + self.bwd_pkts

        # Rates
        flow_bytes_per_sec = tot_bytes / duration_sec
        flow_pkts_per_sec = tot_pkts / duration_sec
        fwd_pkts_per_sec = self.fwd_pkts / duration_sec
        bwd_pkts_per_sec = self.bwd_pkts / duration_sec

        # IATs
        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std, _ = self._stats(self.flow_iats)
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std, _ = self._stats(self.fwd_iats)
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std, _ = self._stats(self.bwd_iats)

        fwd_iat_tot = float(sum(self.fwd_iats))
        bwd_iat_tot = float(sum(self.bwd_iats))

        # Active & Idle
        active_min, active_max, active_mean, active_std, _ = self._stats(self.active_times)
        idle_min, idle_max, idle_mean, idle_std, _ = self._stats(self.idle_times)

        # Down/Up Ratio
        down_up_ratio = (self.bwd_pkts / self.fwd_pkts) if self.fwd_pkts > 0 else 0.0

        # Construct exact 70-feature dictionary
        features = {
            "Destination Port": float(self.dst_port),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(self.fwd_pkts),
            "Total Backward Packets": float(self.bwd_pkts),
            "Total Length of Fwd Packets": tot_fwd_bytes,
            "Total Length of Bwd Packets": tot_bwd_bytes,
            "Fwd Packet Length Max": fwd_len_max,
            "Fwd Packet Length Min": fwd_len_min,
            "Fwd Packet Length Mean": fwd_len_mean,
            "Fwd Packet Length Std": fwd_len_std,
            "Bwd Packet Length Max": bwd_len_max,
            "Bwd Packet Length Min": bwd_len_min,
            "Bwd Packet Length Mean": bwd_len_mean,
            "Bwd Packet Length Std": bwd_len_std,
            "Flow Bytes/s": float(flow_bytes_per_sec),
            "Flow Packets/s": float(flow_pkts_per_sec),
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": float(self.flag_counts["fwd_psh"]),
            "Fwd URG Flags": float(self.flag_counts["fwd_urg"]),
            "Fwd Header Length": float(self.fwd_header_len),
            "Bwd Header Length": float(self.bwd_header_len),
            "Fwd Packets/s": float(fwd_pkts_per_sec),
            "Bwd Packets/s": float(bwd_pkts_per_sec),
            "Min Packet Length": all_len_min,
            "Max Packet Length": all_len_max,
            "Packet Length Mean": all_len_mean,
            "Packet Length Std": all_len_std,
            "Packet Length Variance": all_len_var,
            "FIN Flag Count": float(self.flag_counts["FIN"]),
            "SYN Flag Count": float(self.flag_counts["SYN"]),
            "RST Flag Count": float(self.flag_counts["RST"]),
            "PSH Flag Count": float(self.flag_counts["PSH"]),
            "ACK Flag Count": float(self.flag_counts["ACK"]),
            "URG Flag Count": float(self.flag_counts["URG"]),
            "CWE Flag Count": float(self.flag_counts["CWE"]),
            "ECE Flag Count": float(self.flag_counts["ECE"]),
            "Down/Up Ratio": float(down_up_ratio),
            "Average Packet Size": all_len_mean,
            "Avg Fwd Segment Size": fwd_len_mean,
            "Avg Bwd Segment Size": bwd_len_mean,
            "Fwd Header Length.1": float(self.fwd_header_len),
            "Subflow Fwd Packets": float(self.fwd_pkts),
            "Subflow Fwd Bytes": tot_fwd_bytes,
            "Subflow Bwd Packets": float(self.bwd_pkts),
            "Subflow Bwd Bytes": tot_bwd_bytes,
            "Init_Win_bytes_forward": float(self.init_win_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bwd),
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
            "min_seg_size_forward": float(self.min_seg_size_fwd),
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
        }

        return features
