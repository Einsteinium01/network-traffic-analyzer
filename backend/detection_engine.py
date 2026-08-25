"""
backend/detection_engine.py
===========================
WHY THIS FILE EXISTS
--------------------
Phase 5: Real-Time Intrusion Detection Engine.
Integrates Packet Capture (Phase 3), Feature Extraction (Phase 4), and
Machine Learning Prediction (Phase 2) into a unified real-time pipeline.

HOW IT WORKS
------------
1. Initializes PacketSniffer and FeatureExtractor.
2. Loads trained model (models/model.pkl) and feature columns (models/feature_columns.pkl).
3. As live packets arrive:
   a. Extracts 70-feature flow vector.
   b. Runs ML inference (XGBoost GPU model).
   c. Obtains classification ('BENIGN' vs 'ATTACK') and confidence score (e.g., 99.85%).
   d. Assigns threat severity and pushes alerts to thread-safe queues.
4. Provides live statistics (Total Packets, Normal vs Attack counts, Threat Level).

FILE: backend/detection_engine.py
"""

import time
import pathlib
import logging
import threading
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Tuple

import pandas as pd
import numpy as np
import joblib
import psutil

from packet_capture.sniffer import PacketSniffer
from feature_extraction.extractor import FeatureExtractor

logger = logging.getLogger(__name__)

# Paths
ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = ROOT / "models" / "model.pkl"
DEFAULT_FEATS_PATH = ROOT / "models" / "feature_columns.pkl"


class DetectionEngine:
    """
    Real-Time Intrusion Detection Engine.
    Combines Sniffer + Feature Extractor + XGBoost Classifier.
    """

    def __init__(
        self,
        model_path: Optional[pathlib.Path] = None,
        feature_cols_path: Optional[pathlib.Path] = None,
        max_history: int = 1000,
    ):
        """
        Initialize DetectionEngine.

        :param model_path: Path to models/model.pkl
        :param feature_cols_path: Path to models/feature_columns.pkl
        :param max_history: Max number of recent packets and alerts to hold in memory
        """
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.feature_cols_path = feature_cols_path or DEFAULT_FEATS_PATH
        self.max_history = max_history

        # Load ML Model & Feature Schema
        self.model = self._load_model()
        self.extractor = FeatureExtractor(feature_cols_path=self.feature_cols_path)
        self._warmup_model()

        # Sniffer Instance
        self.sniffer: Optional[PacketSniffer] = None

        # Result History
        self.recent_packets: deque = deque(maxlen=max_history)
        self.recent_alerts: deque = deque(maxlen=max_history)
        self.alert_listeners: List[Callable[[Dict[str, Any]], None]] = []

        # ── Rate tracking (capture thread, wire-speed) ───────────────────────
        self._capture_rate_window: deque = deque()   # (timestamp, bytes)
        self._nic_name: Optional[str] = None
        self._nic_start_sample = None
        self._last_nic_sample = None
        self._last_nic_time: float = 0.0
        self._last_inst_bps: float = 0.0
        self._last_inst_pps: float = 0.0

        # ── Flow-sampler ML thread (replaces per-packet ML queue) ────────────
        # XGBoost runs on each active flow at most once per _sampler_interval seconds.
        # This matches CICIDS2017 training methodology (flow-level features).
        self._sampler_interval: float = 5.0
        self._sampler_thread: Optional[threading.Thread] = None
        self._sampler_stop = threading.Event()

        # Tracks when each flow key was last submitted to XGBoost.
        # Key: 5-tuple flow key. Value: timestamp of last prediction.
        self._flow_last_predicted: Dict[Tuple, float] = {}

        # Protects extractor.active_flows against concurrent access by the
        # capture thread (add_packet) and the sampler thread (read + flush).
        self._extractor_lock = threading.Lock()

        # ── Main stats lock & counters ───────────────────────────────────────
        self._lock = threading.Lock()
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "normal_packets": 0,
            "attack_packets": 0,
            "threat_level": "LOW",
            "start_time": None,
            "last_packet_time": None,
        }

    def _load_model(self) -> Any:
        """Load trained model from model.pkl."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found at {self.model_path}. Please run models/compare_models.py first!"
            )
        try:
            model = joblib.load(self.model_path)
            # Ensure real-time inference uses CPU to prevent CUDA context locks in background threads
            if hasattr(model, "set_params"):
                try:
                    model.set_params(device="cpu")
                except Exception:
                    pass
            logger.info(f"Loaded ML Model from {self.model_path.name}")
            return model
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            raise

    def _warmup_model(self) -> None:
        """Pre-warm CPU model with a dummy input vector."""
        try:
            dummy_df = pd.DataFrame([{col: 0.0 for col in self.extractor.expected_features}])
            self.model.predict(dummy_df)
            if hasattr(self.model, "predict_proba"):
                self.model.predict_proba(dummy_df)
            logger.info("ML Model warmup completed successfully.")
        except Exception as e:
            logger.warning(f"Model warmup warning ({e}).")

    def _infer_attack_type(self, pkt: Dict[str, Any], features_df: pd.DataFrame) -> str:
        """Categorize attack type based on packet features for UI display."""
        dst_port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "TCP")
        length = pkt.get("length", 0)
        flags = pkt.get("tcp_flags") or {}

        if flags.get("SYN") and not flags.get("ACK"):
            return "PortScan / SYN Flood"
        elif dst_port in [80, 443, 8080]:
            return "Web Attack / DoS"
        elif dst_port in [21, 22, 3389]:
            return "Brute Force / Intrusion"
        elif proto == "UDP" and length > 800:
            return "UDP Flood / Volumetric DoS"
        else:
            return "Malicious Traffic / Anomaly"

    def process_packet(self, raw_pkt: Dict[str, Any]) -> None:
        """
        CAPTURE-THREAD callback — must return instantly.
        Updates raw throughput counters and the flow table.
        XGBoost is NEVER called here. Inference runs in the sampler thread.
        """
        now = time.time()
        pkt_len = raw_pkt.get("length", 0)

        # 1. Update raw wire-speed counters (under stats lock)
        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += pkt_len
            self.stats["last_packet_time"] = now
            self._capture_rate_window.append((now, pkt_len))
            cutoff = now - 1.0
            while self._capture_rate_window and self._capture_rate_window[0][0] < cutoff:
                self._capture_rate_window.popleft()

        # 2. Update flow table (under extractor lock — lightweight dict update)
        with self._extractor_lock:
            self.extractor.process_packet(raw_pkt)

    # ── Flow Sampler Thread ───────────────────────────────────────────────────

    def _flow_sampler(self) -> None:
        """
        Background sampler thread. Wakes every _sampler_interval seconds.
        - Flushes expired flows (FIN/RST, idle timeout, max duration) and predicts on them.
        - Samples all remaining active flows and predicts on any not predicted in the last interval.
        This is the ONLY place XGBoost is called.
        """
        while not self._sampler_stop.wait(self._sampler_interval):
            try:
                self._sample_and_predict_flows()
            except Exception as e:
                logger.error(f"Flow sampler error: {e}")

    def _sample_and_predict_flows(self) -> None:
        """
        One sampling cycle: flush expired flows + predict on all eligible active flows.
        """
        now = time.time()

        # ── Step 1: Flush expired flows (FIN/RST, idle, max-duration) ────────
        with self._extractor_lock:
            expired_flows = self.extractor.flush_expired_flows(current_time=now)
            # Snapshot active flow keys + references for prediction below
            active_snapshot = list(self.extractor.active_flows.items())

        # Predict on expired flows immediately (they won't be seen again)
        for flow, _feat_dict in expired_flows:
            flow_key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol)
            self._predict_flow(flow, flow_key, now, is_expired=True)
            # Remove stale prediction timestamp to avoid leaking memory
            self._flow_last_predicted.pop(flow_key, None)

        # ── Step 2: Sample active flows that haven't been predicted recently ──
        for flow_key, flow in active_snapshot:
            last_predicted = self._flow_last_predicted.get(flow_key, 0.0)
            if (now - last_predicted) >= self._sampler_interval:
                # Only predict on flows with at least 2 packets (meaningful features)
                if (flow.fwd_pkts + flow.bwd_pkts) >= 2:
                    self._predict_flow(flow, flow_key, now, is_expired=False)
                    self._flow_last_predicted[flow_key] = now

        # Clean up prediction timestamps for flows that are no longer active
        active_keys = {k for k, _ in active_snapshot}
        stale_keys = [k for k in self._flow_last_predicted if k not in active_keys]
        for k in stale_keys:
            del self._flow_last_predicted[k]

    def _predict_flow(
        self,
        flow: Any,
        flow_key: tuple,
        now: float,
        is_expired: bool,
    ) -> None:
        """
        Run XGBoost inference on a single flow and broadcast the result.
        Called exclusively from the sampler thread — never from the capture thread.
        """
        is_attack = False
        confidence = 0.95
        confidence_pct = 95.0
        label_str = "BENIGN"
        attack_type = "BENIGN"

        try:
            features_df = self.extractor.extract_features(flow)
            pred_class = int(self.model.predict(features_df)[0])

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(features_df)[0]
                confidence = float(np.max(probs))
            else:
                confidence = 1.0

            is_attack = (pred_class == 1)
            label_str = "ATTACK" if is_attack else "BENIGN"
            confidence_pct = round(confidence * 100.0, 2)

            if is_attack:
                # Build a minimal pkt-like dict for attack type inference
                pkt_proxy = {
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "length": int(flow.avg_pkt_length),
                    "tcp_flags": {},
                }
                attack_type = self._infer_attack_type(pkt_proxy, features_df)

        except Exception as e:
            logger.error(f"XGBoost inference error on flow {flow_key}: {e}")
            return

        result = {
            "id": f"flow-{int(now * 1000)}-{np.random.randint(100, 999)}",
            "timestamp": now,
            "timestamp_str": datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3],
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "length": int(flow.avg_pkt_length),
            "prediction": label_str,
            "is_attack": is_attack,
            "confidence": confidence,
            "confidence_pct": confidence_pct,
            "attack_type": attack_type,
            "is_simulated": False,
            "flow_packets": flow.fwd_pkts + flow.bwd_pkts,
            "flow_expired": is_expired,
        }

        # Update detection statistics
        with self._lock:
            if is_attack:
                self.stats["attack_packets"] += 1
                self.recent_alerts.append(result)
            else:
                self.stats["normal_packets"] += 1
            self.recent_packets.append(result)
            self._update_threat_level()

        # Broadcast to SocketIO listeners (app.py _broadcast_packet)
        for listener in self.alert_listeners:
            try:
                listener(result)
            except Exception as e:
                logger.error(f"Error in alert listener: {e}")

    def _update_threat_level(self) -> None:
        """Update threat level based on recent attack traffic ratio."""
        if not self.recent_packets:
            self.stats["threat_level"] = "LOW"
            return

        recent_sample = list(self.recent_packets)[-50:]
        attack_count = sum(1 for p in recent_sample if p.get("is_attack"))
        ratio = attack_count / len(recent_sample)

        if ratio >= 0.40:
            self.stats["threat_level"] = "CRITICAL"
        elif ratio >= 0.20:
            self.stats["threat_level"] = "HIGH"
        elif ratio >= 0.05:
            self.stats["threat_level"] = "MEDIUM"
        else:
            self.stats["threat_level"] = "LOW"

    def register_alert_listener(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback handler for real-time WebSocket broadcasting."""
        if callback not in self.alert_listeners:
            self.alert_listeners.append(callback)

    def _resolve_nic_name(self, interface: Optional[str]) -> Optional[str]:
        """Resolve interface name to a valid key in psutil.net_io_counters()."""
        try:
            counters = psutil.net_io_counters(pernic=True)
            if interface and interface != "Auto":
                if interface in counters:
                    return interface
                for k in counters.keys():
                    if interface.lower() in k.lower() or k.lower() in interface.lower():
                        return k

            # Auto-detect active UP interface with non-loopback IPv4
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for name, st in stats.items():
                if st.isup and name in counters and name in addrs:
                    for a in addrs[name]:
                        if getattr(a.family, "name", str(a.family)) == "AF_INET" and a.address != "127.0.0.1":
                            return name
            return list(counters.keys())[0] if counters else None
        except Exception as e:
            logger.debug(f"NIC resolution error: {e}")
            return None

    def start(self, mode: str = "LIVE", interface: Optional[str] = None) -> None:
        """Start PacketSniffer and feed packets directly into DetectionEngine."""
        if self.sniffer and self.sniffer.is_running():
            logger.warning("DetectionEngine is already running.")
            return

        with self._lock:
            self.stats["start_time"] = time.time()
            self.stats["total_packets"] = 0
            self.stats["total_bytes"] = 0
            self.stats["normal_packets"] = 0
            self.stats["attack_packets"] = 0
            self.stats["threat_level"] = "LOW"
            self._capture_rate_window.clear()

            # Initialize NIC hardware counters for true wire throughput & total counts
            if mode == "LIVE":
                self._nic_name = self._resolve_nic_name(interface)
                if self._nic_name:
                    counters = psutil.net_io_counters(pernic=True)
                    self._nic_start_sample = counters.get(self._nic_name)
                    self._last_nic_sample = counters.get(self._nic_name)
                    self._last_nic_time = time.time()
                    self._last_inst_bps = 0.0
                    self._last_inst_pps = 0.0
                else:
                    self._nic_start_sample = None
            else:
                self._nic_name = None
                self._nic_start_sample = None
                self._last_nic_sample = None

        self.recent_packets.clear()
        self.recent_alerts.clear()
        self.extractor.clear()
        self._flow_last_predicted.clear()

        # Start flow-sampler thread (periodic XGBoost on active flows)
        self._sampler_stop.clear()
        self._sampler_thread = threading.Thread(
            target=self._flow_sampler, daemon=True, name="FlowSamplerThread"
        )
        self._sampler_thread.start()

        # Instantiate Sniffer with self.process_packet callback (fast, non-blocking)
        self.sniffer = PacketSniffer(
            interface=interface,
            mode=mode,
            callback=self.process_packet,
        )
        self.sniffer.start()

        # Check if starting succeeded
        if not self.sniffer.is_running() and self.sniffer.error_message:
            self._sampler_stop.set()
            raise RuntimeError(self.sniffer.error_message)

        logger.info(
            f"DetectionEngine started (Mode: [{self.sniffer.active_mode}], "
            f"NIC: [{self._nic_name}], ML sampler interval: {self._sampler_interval}s)."
        )

    def stop(self) -> None:
        """Stop detection engine and flow sampler thread."""
        if self.sniffer and self.sniffer.is_running():
            self.sniffer.stop()

        # Signal sampler to stop and wait briefly
        self._sampler_stop.set()
        if self._sampler_thread and self._sampler_thread.is_alive():
            self._sampler_thread.join(timeout=self._sampler_interval + 1.0)
        logger.info("DetectionEngine stopped.")


    def is_running(self) -> bool:
        """Check if detection engine is running."""
        return self.sniffer is not None and self.sniffer.is_running()

    def get_live_stats(self) -> Dict[str, Any]:
        """Return live metrics and threat assessment."""
        with self._lock:
            attack = self.stats["attack_packets"]
            start_ts = self.stats["start_time"] or time.time()
            now = time.time()
            duration = max(now - start_ts, 0.001)

            # ── Instantaneous & Total throughput calculation ─────────────────
            # In LIVE mode, measure exact hardware NIC metrics from OS counters (100% true rate)
            if self._nic_name and self.is_running():
                try:
                    counters = psutil.net_io_counters(pernic=True)
                    curr_nic = counters.get(self._nic_name)
                    if curr_nic:
                        # Compute exact total packets & bytes since monitoring started
                        if getattr(self, "_nic_start_sample", None):
                            total_pkts = max(
                                (curr_nic.packets_recv + curr_nic.packets_sent)
                                - (self._nic_start_sample.packets_recv + self._nic_start_sample.packets_sent),
                                0,
                            )
                            total_bytes = max(
                                (curr_nic.bytes_recv + curr_nic.bytes_sent)
                                - (self._nic_start_sample.bytes_recv + self._nic_start_sample.bytes_sent),
                                0,
                            )
                        else:
                            total_pkts = self.stats["total_packets"]
                            total_bytes = self.stats["total_bytes"]

                        # Compute instantaneous rate
                        if self._last_nic_sample:
                            dt = now - self._last_nic_time
                            if dt >= 0.35:
                                delta_bytes = (curr_nic.bytes_recv + curr_nic.bytes_sent) - (
                                    self._last_nic_sample.bytes_recv + self._last_nic_sample.bytes_sent
                                )
                                delta_pkts = (curr_nic.packets_recv + curr_nic.packets_sent) - (
                                    self._last_nic_sample.packets_recv + self._last_nic_sample.packets_sent
                                )
                                if delta_bytes >= 0:
                                    self._last_inst_bps = round(delta_bytes / dt, 2)
                                if delta_pkts >= 0:
                                    self._last_inst_pps = round(delta_pkts / dt, 2)
                                self._last_nic_sample = curr_nic
                                self._last_nic_time = now
                        else:
                            self._last_nic_sample = curr_nic
                            self._last_nic_time = now
                    else:
                        total_pkts = self.stats["total_packets"]
                        total_bytes = self.stats["total_bytes"]
                except Exception as e:
                    logger.debug("Error sampling NIC counters: %s", e)
                    total_pkts = self.stats["total_packets"]
                    total_bytes = self.stats["total_bytes"]

                inst_bps = self._last_inst_bps
                inst_pps = self._last_inst_pps
            else:
                # Fallback / Simulation rate from rolling 1-second window
                total_pkts = self.stats["total_packets"]
                total_bytes = self.stats["total_bytes"]
                cutoff = now - 1.0
                recent_bytes = sum(b for t, b in self._capture_rate_window if t >= cutoff)
                recent_pkts = sum(1 for t, b in self._capture_rate_window if t >= cutoff)
                window_len = max(min(duration, 1.0), 0.1)
                inst_pps = round(recent_pkts / window_len, 2)
                inst_bps = round(recent_bytes / window_len, 2)

            normal = max(total_pkts - attack, 0)
            normal_pct = round((normal / total_pkts * 100.0), 2) if total_pkts > 0 else 100.0
            attack_pct = round((attack / total_pkts * 100.0), 2) if total_pkts > 0 else 0.0

            sniffer_stats = self.sniffer.get_stats() if self.sniffer else {}
            active_flows_count = len(self.extractor.active_flows)

            return {
                "is_running": self.is_running(),
                "capture_mode": sniffer_stats.get("capture_mode", "LIVE"),
                "interface": sniffer_stats.get("interface", "Auto"),
                "error_message": sniffer_stats.get("error_message"),
                "total_packets": total_pkts,
                "total_bytes": total_bytes,
                "normal_packets": normal,
                "attack_packets": attack,
                "normal_pct": normal_pct,
                "attack_pct": attack_pct,
                "threat_level": self.stats["threat_level"],
                "duration_seconds": round(duration, 2),
                "packets_per_second": inst_pps,
                "bytes_per_second": inst_bps,
                "active_flows": active_flows_count,
                "tcp_count": sniffer_stats.get("tcp_count", 0),
                "udp_count": sniffer_stats.get("udp_count", 0),
                "icmp_count": sniffer_stats.get("icmp_count", 0),
            }

    def get_recent_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent processed packets."""
        with self._lock:
            return list(self.recent_packets)[-limit:]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent threat alerts."""
        with self._lock:
            return list(self.recent_alerts)[-limit:]

