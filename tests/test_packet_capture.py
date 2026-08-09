"""
tests/test_packet_capture.py
=============================
Pytest suite for Phase 3 – Packet Capture module.
"""

import time
import pytest
from packet_capture import PacketSniffer, get_available_interfaces, format_packet_info


def test_get_available_interfaces():
    ifaces = get_available_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "name" in ifaces[0]


def test_packet_sniffer_lifecycle():
    packets = []
    sniffer = PacketSniffer(mode="simulation", callback=lambda p: packets.append(p))

    assert not sniffer.is_running()
    sniffer.start()
    assert sniffer.is_running()

    time.sleep(1.0)
    sniffer.stop()
    assert not sniffer.is_running()

    stats = sniffer.get_stats()
    assert stats["total_packets"] > 0
    assert len(packets) > 0

    pkt = packets[0]
    assert "src_ip" in pkt
    assert "dst_ip" in pkt
    assert "protocol" in pkt
    assert "length" in pkt
    assert "timestamp" in pkt

    formatted = format_packet_info(pkt)
    assert isinstance(formatted, str)
    assert pkt["protocol"] in formatted


def test_protocol_filtering():
    tcp_packets = []
    sniffer = PacketSniffer(filter_proto="TCP", mode="simulation", callback=lambda p: tcp_packets.append(p))
    sniffer.start()
    time.sleep(1.0)
    sniffer.stop()

    for pkt in tcp_packets:
        assert pkt["protocol"] == "TCP"
