"""
test_capture.py
===============
WHY THIS FILE EXISTS
--------------------
Independent test script for Phase 3: Packet Capture.
Verifies that PacketSniffer can capture TCP, UDP, and ICMP packets,
extract required header fields, format output, and report live stats.

HOW TO RUN
----------
  python packet_capture/test_capture.py

EXPECTED OUTPUT
---------------
  - Printed stream of packets with Timestamp, Protocol, Src IP:Port -> Dst IP:Port, Length.
  - Final summary statistics table (Total Packets, TCP, UDP, ICMP counts, Rate).
"""

import time
import sys
import pathlib

# Ensure project root is in python path
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packet_capture.sniffer import PacketSniffer
from packet_capture.utils import format_packet_info, get_available_interfaces


def main():
    print("=" * 70)
    print("Phase 3 – Independent Packet Capture Test")
    print("=" * 70)

    # 1. Discover available network interfaces
    interfaces = get_available_interfaces()
    print("Available Network Interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"  [{idx}] {iface.get('name')} -> IP: {iface.get('ip')}")
    print("-" * 70)

    # 2. Instantiate Sniffer
    captured_packets = []

    def packet_callback(pkt):
        captured_packets.append(pkt)
        print("  " + format_packet_info(pkt))

    print("Initializing PacketSniffer (auto mode)...")
    sniffer = PacketSniffer(mode="auto", callback=packet_callback)

    # 3. Start Capture
    print(f"Starting PacketSniffer...")
    sniffer.start()
    print(f"Active Mode: [{sniffer.active_mode.upper()}]")
    print("Capturing live traffic for 5 seconds (TCP / UDP / ICMP)...\n")

    time.sleep(5.0)

    # 4. Stop Capture
    print("\nStopping PacketSniffer...")
    sniffer.stop()

    # 5. Review & Display Statistics
    stats = sniffer.get_stats()
    print("\n" + "=" * 70)
    print("Packet Capture Statistics Summary")
    print("=" * 70)
    print(f"  Capture Mode       : {stats['active_mode'].upper()}")
    print(f"  Duration           : {stats['duration_seconds']} seconds")
    print(f"  Total Packets      : {stats['total_packets']}")
    print(f"  TCP Packets        : {stats['tcp_count']}")
    print(f"  UDP Packets        : {stats['udp_count']}")
    print(f"  ICMP Packets       : {stats['icmp_count']}")
    print(f"  Other Packets      : {stats['other_count']}")
    print(f"  Total Bytes        : {stats['total_bytes']} bytes")
    print(f"  Packet Rate        : {stats['packets_per_second']} packets/sec")
    print(f"  Data Rate          : {stats['bytes_per_second']} bytes/sec")
    print("=" * 70)

    # Sanity Assertions
    assert stats["total_packets"] > 0, "Error: No packets were captured!"
    assert len(captured_packets) == stats["total_packets"], "Mismatch in callback packet count!"

    first_pkt = captured_packets[0]
    required_keys = ["timestamp", "src_ip", "dst_ip", "protocol", "length"]
    for key in required_keys:
        assert key in first_pkt, f"Missing required key '{key}' in captured packet dictionary!"

    print("\nSUCCESS: All Phase 3 Packet Capture assertions passed!")


if __name__ == "__main__":
    main()
