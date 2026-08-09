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

        # Data Queues & Storage
        self.recent_packets: deque = deque(maxlen=max_history)
        self.recent_alerts: deque = deque(maxlen=max_history)
        self.alert_listeners: List[Callable[[Dict[str, Any]], None]] = []

        # Lock & Live Statistics
        self._lock = threading.Lock()
        self.stats = {
            "total_packets": 0,
            "normal_packets": 0,
            "attack_packets": 0,
            "threat_level": "LOW",  # LOW, MEDIUM, HIGH, CRITICAL
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
        """Pre-warm GPU/CPU model with a dummy input vector."""
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

    def process_packet(self, raw_pkt: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single raw packet dictionary through the detection pipeline:
        Feature Extraction -> ML Prediction -> Confidence Scoring -> Alerting.
        """
        # 1. Feature Extraction (70 features)
        features_df = self.extractor.extract_features(raw_pkt)

        # 2. ML Prediction (0 = BENIGN, 1 = ATTACK)
        try:
            pred_class = int(self.model.predict(features_df)[0])

            # Get Confidence Score (%)
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(features_df)[0]
                confidence = float(np.max(probs))
            else:
                confidence = 1.0
        except Exception as e:
            logger.error(f"ML Inference Error ({e}). Defaulting to Benign.")
            pred_class = 0
            confidence = 0.50

        is_attack = (pred_class == 1)
        label_str = "ATTACK" if is_attack else "BENIGN"
        confidence_pct = round(confidence * 100.0, 2)

        attack_type = "BENIGN"
        if is_attack:
            attack_type = self._infer_attack_type(raw_pkt, features_df)

        # 3. Construct Unified Inspection Result
        now = time.time()
        result = {
            "id": f"pkt-{int(now * 1000)}-{np.random.randint(100, 999)}",
            "timestamp": now,
            "timestamp_str": raw_pkt.get(
                "timestamp_str",
                datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]
            ),
            "src_ip": raw_pkt.get("src_ip", "0.0.0.0"),
            "dst_ip": raw_pkt.get("dst_ip", "0.0.0.0"),
            "src_port": raw_pkt.get("src_port", 0),
            "dst_port": raw_pkt.get("dst_port", 0),
            "protocol": raw_pkt.get("protocol", "OTHER"),
            "length": raw_pkt.get("length", 0),
            "prediction": label_str,
            "is_attack": is_attack,
            "confidence": confidence,
            "confidence_pct": confidence_pct,
            "attack_type": attack_type,
        }

        # 4. Update Statistics & Queues
        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["last_packet_time"] = now

            if is_attack:
                self.stats["attack_packets"] += 1
                self.recent_alerts.append(result)
            else:
                self.stats["normal_packets"] += 1

            self.recent_packets.append(result)
            self._update_threat_level()

        # 5. Notify Listeners (if attack detected or for stream)
        for listener in self.alert_listeners:
            try:
                listener(result)
            except Exception as e:
                logger.error(f"Error in alert listener callback: {e}")

        return result

    def _update_threat_level(self) -> None:
        """Update threat level based on recent attack traffic ratio."""
        if not self.recent_packets:
            self.stats["threat_level"] = "LOW"
            return

        # Look at last 50 packets
        recent_sample = list(self.recent_packets)[-50:]
        attack_count = sum(1 for p in recent_sample if p["is_attack"])
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

    def start(self, mode: str = "auto", interface: Optional[str] = None) -> None:
        """Start PacketSniffer and feed packets directly into DetectionEngine."""
        if self.sniffer and self.sniffer.is_running():
            logger.warning("DetectionEngine is already running.")
            return

        with self._lock:
            self.stats["start_time"] = time.time()
            self.stats["total_packets"] = 0
            self.stats["normal_packets"] = 0
            self.stats["attack_packets"] = 0
            self.stats["threat_level"] = "LOW"

        self.recent_packets.clear()
        self.recent_alerts.clear()

        # Instantiate Sniffer with self.process_packet callback
        self.sniffer = PacketSniffer(
            interface=interface,
            mode=mode,
            callback=self.process_packet,
        )
        self.sniffer.start()
        logger.info(f"DetectionEngine started (Sniffer Mode: [{self.sniffer.active_mode.upper()}]).")

    def stop(self) -> None:
        """Stop detection engine."""
        if self.sniffer and self.sniffer.is_running():
            self.sniffer.stop()
            logger.info("DetectionEngine stopped.")

    def is_running(self) -> bool:
        """Check if detection engine is running."""
        return self.sniffer is not None and self.sniffer.is_running()

    def get_live_stats(self) -> Dict[str, Any]:
        """Return live metrics and threat assessment."""
        with self._lock:
            total = self.stats["total_packets"]
            normal = self.stats["normal_packets"]
            attack = self.stats["attack_packets"]
            start_ts = self.stats["start_time"] or time.time()
            duration = max(time.time() - start_ts, 0.001)

            normal_pct = round((normal / total * 100.0), 2) if total > 0 else 100.0
            attack_pct = round((attack / total * 100.0), 2) if total > 0 else 0.0

            sniffer_stats = self.sniffer.get_stats() if self.sniffer else {}

            return {
                "is_running": self.is_running(),
                "mode": sniffer_stats.get("active_mode", "N/A"),
                "total_packets": total,
                "normal_packets": normal,
                "attack_packets": attack,
                "normal_pct": normal_pct,
                "attack_pct": attack_pct,
                "threat_level": self.stats["threat_level"],
                "duration_seconds": round(duration, 2),
                "packets_per_second": round(total / duration, 2),
                "bytes_per_second": sniffer_stats.get("bytes_per_second", 0),
            }

    def get_recent_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent processed packets."""
        with self._lock:
            return list(self.recent_packets)[-limit:]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent threat alerts."""
        with self._lock:
            return list(self.recent_alerts)[-limit:]
