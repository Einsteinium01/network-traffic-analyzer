"""
packet_capture/utils.py
=======================
WHY THIS FILE EXISTS
--------------------
Utility functions for parsing raw packet headers, listing system network
interfaces, formatting packet outputs for human display, and detecting
available capture backends.

HOW IT WORKS
------------
- Uses Python's struct module to unpack IPv4, TCP, UDP, and ICMP headers.
- Converts protocol numbers (6 -> TCP, 17 -> UDP, 1 -> ICMP) to readable names.
- Formats timestamps to ISO 8601 string format.

FILE: packet_capture/utils.py
"""

import socket
import struct
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

# Protocol Mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def get_protocol_name(proto_num: int) -> str:
    """Convert protocol number to human-readable string."""
    return PROTOCOL_MAP.get(proto_num, f"OTHER({proto_num})")


def parse_ip_header(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a raw IPv4 header (first 20 bytes minimum).

    Header Format (20 bytes):
      0: Version (4 bits) + IHL (4 bits)
      1: Type of Service
      2-3: Total Length
      4-5: Identification
      6-7: Flags (3 bits) + Fragment Offset (13 bits)
      8: TTL
      9: Protocol
      10-11: Header Checksum
      12-15: Source IP
      16-19: Destination IP
    """
    if len(data) < 20:
        return None

    try:
        iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4  # Header length in bytes

        if version != 4:  # Only IPv4 supported in standard raw header parser
            return None

        total_length = iph[2]
        ttl = iph[5]
        protocol_num = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        return {
            "version": version,
            "ihl": ihl,
            "total_length": total_length,
            "ttl": ttl,
            "protocol_num": protocol_num,
            "protocol": get_protocol_name(protocol_num),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": data[ihl:],
        }
    except Exception:
        return None


def parse_transport_header(protocol: str, payload: bytes) -> Dict[str, Any]:
    """
    Parse transport layer headers (TCP, UDP, ICMP).

    Returns ports, flags, and header-specific metadata.
    """
    info: Dict[str, Any] = {
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
    }

    if protocol == "TCP" and len(payload) >= 20:
        tcph = struct.unpack("!HHLLBBHHH", payload[:20])
        info["src_port"] = tcph[0]
        info["dst_port"] = tcph[1]
        flags_byte = tcph[5]
        info["tcp_flags"] = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }

    elif protocol == "UDP" and len(payload) >= 8:
        udph = struct.unpack("!HHHH", payload[:8])
        info["src_port"] = udph[0]
        info["dst_port"] = udph[1]

    elif protocol == "ICMP" and len(payload) >= 2:
        icmph = struct.unpack("!BB", payload[:2])
        info["icmp_type"] = icmph[0]
        info["icmp_code"] = icmph[1]

    return info


def format_packet_info(pkt: Dict[str, Any]) -> str:
    """
    Format packet dictionary into a clean console log string.
    """
    ts_str = pkt.get("timestamp_str", datetime.now().strftime("%H:%M:%S.%f")[:-3])
    src = f"{pkt.get('src_ip', '0.0.0.0')}:{pkt.get('src_port', 0)}" if pkt.get("src_port") else pkt.get("src_ip", "0.0.0.0")
    dst = f"{pkt.get('dst_ip', '0.0.0.0')}:{pkt.get('dst_port', 0)}" if pkt.get("dst_port") else pkt.get("dst_ip", "0.0.0.0")
    proto = pkt.get("protocol", "UNKNOWN")
    length = pkt.get("length", 0)

    return f"[{ts_str}] {proto:<5} {src:<21} -> {dst:<21} Len: {length:<5} bytes"


def get_available_interfaces() -> List[Dict[str, str]]:
    """
    Return a list of available network interfaces on the local machine.
    """
    interfaces = []
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        interfaces.append({"name": "Default Local IP", "ip": local_ip})
    except Exception:
        pass

    try:
        import scapy.all as scapy
        for iface in scapy.get_working_ifaces():
            interfaces.append({
                "name": iface.name,
                "ip": getattr(iface, "ip", "N/A"),
                "mac": getattr(iface, "mac", "N/A")
            })
    except Exception:
        pass

    if not interfaces:
        interfaces.append({"name": "Loopback / Default", "ip": "127.0.0.1"})

    return interfaces
