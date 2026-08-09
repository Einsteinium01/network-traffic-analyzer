"""
test_detection.py
=================
WHY THIS FILE EXISTS
--------------------
Independent test script for Phase 5: Detection Engine.
Verifies the complete real-time detection pipeline:
Packet Capture -> Feature Extraction -> XGBoost Model Prediction -> Confidence Scoring.

HOW TO RUN
----------
  python backend/test_detection.py

EXPECTED OUTPUT
---------------
  - Stream of live packets classified as BENIGN or ATTACK with confidence scores %.
  - Live statistics summary showing Total Packets, Normal %, Attack %, and Threat Level.
"""

import time
import sys
import pathlib

# Add project root to python path
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detection_engine import DetectionEngine


def main():
    print("=" * 70)
    print("Phase 5 – Independent Real-Time Detection Engine Test")
    print("=" * 70)

    # 1. Initialize DetectionEngine
    print("Initializing Detection Engine & loading ML model (model.pkl)...")
    engine = DetectionEngine()

    # 2. Register real-time alert callback printer
    packet_stream = []

    def alert_listener(result):
        packet_stream.append(result)
        status_tag = f"[{result['prediction']}]" if not result['is_attack'] else f"[{result['prediction']} - {result['attack_type']}]"
        src = f"{result['src_ip']}:{result['src_port']}" if result['src_port'] else result['src_ip']
        dst = f"{result['dst_ip']}:{result['dst_port']}" if result['dst_port'] else result['dst_ip']

        color_prefix = "\033[92m" if not result['is_attack'] else "\033[91m"
        reset_suffix = "\033[0m"

        print(
            f"  [{result['timestamp_str']}] {result['protocol']:<5} {src:<21} -> {dst:<21} "
            f"{status_tag:<30} Conf: {result['confidence_pct']:>6.2f}%"
        )

    engine.register_alert_listener(alert_listener)

    # 3. Start Detection Engine
    print("\nStarting DetectionEngine (Live Sniffer + Feature Extractor + XGBoost GPU Model)...")
    engine.start(mode="simulation")

    print("Analyzing traffic for 5 seconds...\n")
    time.sleep(5.0)

    # 4. Stop Detection Engine
    print("\nStopping DetectionEngine...")
    engine.stop()

    # 5. Summary & Assertions
    stats = engine.get_live_stats()
    alerts = engine.get_alerts()

    print("\n" + "=" * 70)
    print("Real-Time Detection Engine Statistics Summary")
    print("=" * 70)
    print(f"  Sniffer Mode       : {stats['mode'].upper()}")
    print(f"  Duration           : {stats['duration_seconds']} seconds")
    print(f"  Total Packets      : {stats['total_packets']}")
    print(f"  Normal Traffic     : {stats['normal_packets']} ({stats['normal_pct']}%)")
    print(f"  Attack Traffic     : {stats['attack_packets']} ({stats['attack_pct']}%)")
    print(f"  Threat Level       : {stats['threat_level']}")
    print(f"  Packet Rate        : {stats['packets_per_second']} packets/sec")
    print(f"  Total Alerts Logged: {len(alerts)}")
    print("=" * 70)

    # Assertions
    assert stats["total_packets"] > 0, "Error: No packets were processed by DetectionEngine!"
    assert len(packet_stream) == stats["total_packets"], "Mismatch in processed packet callback count!"

    first_pkt = packet_stream[0]
    required_keys = ["prediction", "is_attack", "confidence", "confidence_pct", "attack_type"]
    for key in required_keys:
        assert key in first_pkt, f"Missing required key '{key}' in detection output!"

    print("\nSUCCESS: All Phase 5 Detection Engine assertions passed!")


if __name__ == "__main__":
    main()
