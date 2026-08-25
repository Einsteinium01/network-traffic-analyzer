"""
packet_capture/sniffer.py
=========================
WHY THIS FILE EXISTS
--------------------
Provides a multi-engine, non-blocking PacketSniffer class that captures
TCP, UDP, and ICMP packets live from network interfaces or via simulation.

HOW IT WORKS
------------
1. Runs in a dedicated background thread to prevent UI/API blocking.
2. Captures packets using Scapy, Raw Sockets, or Simulation engine.
3. Extracts core properties for each packet:
   - Source IP
   - Destination IP
   - Protocol (TCP, UDP, ICMP)
   - Source & Destination Ports
   - Packet Length (bytes)
   - Timestamp (Epoch float & ISO string)
4. Pushes packets into a thread-safe Queue and executes optional callbacks.
5. Tracks live packet metrics (total count, protocol breakdown, bytes/sec).

FILE: packet_capture/sniffer.py
"""

import sys
import time
import socket
import struct
import random
import logging
import threading
import ctypes
from ctypes import (
    Structure, POINTER, c_char_p, c_void_p, c_int, c_uint, c_ubyte,
    byref, create_string_buffer, string_at
)
from queue import Queue, Empty
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Tuple

from packet_capture.utils import (
    parse_ip_header,
    parse_transport_header,
    format_packet_info,
    get_protocol_name,
)

# Logging Setup
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Npcap C-Types Structures & Helper
# ---------------------------------------------------------------------------
class _pcap_if(Structure):
    pass

_pcap_if._fields_ = [
    ('next', POINTER(_pcap_if)),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', c_void_p),
    ('flags', c_uint)
]


def _load_wpcap_dll():
    """Load wpcap.dll from System32 or PATH."""
    paths = ['wpcap.dll', r'C:\Windows\System32\Npcap\wpcap.dll', r'C:\Windows\System32\wpcap.dll']
    for p in paths:
        try:
            dll = ctypes.cdll.LoadLibrary(p)
            dll.pcap_lib_version.restype = c_char_p
            dll.pcap_findalldevs.argtypes = [POINTER(POINTER(_pcap_if)), c_char_p]
            dll.pcap_findalldevs.restype = c_int
            dll.pcap_freealldevs.argtypes = [POINTER(_pcap_if)]
            dll.pcap_freealldevs.restype = None
            dll.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
            dll.pcap_open_live.restype = c_void_p
            dll.pcap_close.argtypes = [c_void_p]
            dll.pcap_close.restype = None
            dll.pcap_next_ex.argtypes = [c_void_p, POINTER(c_void_p), POINTER(POINTER(c_ubyte))]
            dll.pcap_next_ex.restype = c_int
            dll.pcap_setbuff.argtypes = [c_void_p, c_int]
            dll.pcap_setbuff.restype = c_int
            return dll
        except Exception:
            continue
    return None


class PacketSniffer:
    """
    Thread-safe packet sniffer supporting Npcap ctypes (High-Speed LIVE),
    Scapy (Legacy LIVE), Raw Socket, and SIMULATION modes.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        filter_proto: Optional[str] = None,
        mode: str = "LIVE",
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_queue_size: int = 1000,
    ):
        """
        Initialize PacketSniffer.

        :param interface: Network interface name (e.g. 'Wi-Fi') or None/auto
        :param filter_proto: Protocol filter ('TCP', 'UDP', 'ICMP', or None)
        :param mode: 'LIVE', 'SIMULATION', 'NPCAP', 'SCAPY', 'RAW_SOCKET', 'AUTO'
        :param callback: Callback function invoked on every captured packet dict
        :param max_queue_size: Max buffer capacity for packet queue
        """
        self.requested_mode = mode.upper() if mode else "LIVE"
        self.interface = self._resolve_interface(interface)
        self.filter_proto = filter_proto.upper() if filter_proto else None
        self.active_mode = "LIVE" if self.requested_mode in ("LIVE", "AUTO", "NPCAP", "SCAPY", "RAW_SOCKET") else "SIMULATION"
        self.callback = callback
        self.max_queue_size = max_queue_size
        self.error_message: Optional[str] = None

        self.packet_queue: Queue = Queue(maxsize=max_queue_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Statistics
        self._lock = threading.Lock()
        self.stats = {
            "total_packets": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "other_count": 0,
            "total_bytes": 0,
            "start_time": None,
            "stop_time": None,
        }

    def _resolve_interface(self, iface_input: Optional[str]) -> Optional[str]:
        """Resolve requested interface name or pick best active interface if auto/None."""
        if iface_input and iface_input.strip().lower() not in ("auto", "none", ""):
            return iface_input.strip()

        # Find best active UP IPv4 interface
        try:
            import psutil
            net_addrs = psutil.net_if_addrs()
            net_stats = psutil.net_if_stats()

            for name, addrs in net_addrs.items():
                stat = net_stats.get(name)
                if stat and stat.isup and not ("loopback" in name.lower()):
                    for addr in addrs:
                        if getattr(addr.family, "name", str(addr.family)) == "AF_INET" and addr.address != "127.0.0.1":
                            return name
        except Exception:
            pass

        return None

    def _determine_engine(self) -> str:
        """Determine engine for capture. Returns 'npcap', 'scapy', 'raw_socket', or 'simulation'."""
        if self.requested_mode == "SIMULATION":
            return "simulation"

        # 1. Primary High-Throughput Engine: Npcap via Ctypes
        if self.requested_mode in ("LIVE", "AUTO", "NPCAP"):
            dll = _load_wpcap_dll()
            if dll:
                return "npcap"
            elif self.requested_mode == "NPCAP":
                raise RuntimeError("Npcap is not installed or wpcap.dll could not be loaded.")

        # 2. Fallback Engine: Scapy
        if self.requested_mode in ("LIVE", "SCAPY"):
            try:
                import scapy.all as scapy
                return "scapy"
            except ImportError:
                if self.requested_mode == "SCAPY":
                    raise RuntimeError("Scapy is not installed. Please run: pip install scapy")

        # 3. Fallback Engine: Raw Socket
        if self.requested_mode in ("LIVE", "RAW_SOCKET"):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.close()
                return "raw_socket"
            except Exception as e:
                if self.requested_mode == "RAW_SOCKET":
                    raise RuntimeError(f"Raw socket permission denied: {e}")

        # If LIVE mode was explicitly requested but no backend works, throw explicit error
        if self.requested_mode in ("LIVE", "NPCAP", "SCAPY", "RAW_SOCKET"):
            raise RuntimeError("LIVE capture failed: Npcap/Scapy hardware backend unavailable.")

        return "simulation"


    def start(self) -> None:
        """Start packet capture in a background thread."""
        if self._running:
            logger.warning("PacketSniffer is already running.")
            return

        self.error_message = None
        engine_type = self._determine_engine()
        self.active_mode = "SIMULATION" if engine_type == "simulation" else "LIVE"

        self._running = True
        self._stop_event.clear()

        with self._lock:
            self.stats = {
                "total_packets": 0,
                "tcp_count": 0,
                "udp_count": 0,
                "icmp_count": 0,
                "other_count": 0,
                "total_bytes": 0,
                "start_time": time.time(),
                "stop_time": None,
            }

        target_map = {
            "npcap": self._npcap_capture_loop,
            "scapy": self._scapy_capture_loop,
            "raw_socket": self._raw_socket_capture_loop,
            "simulation": self._simulation_capture_loop,
        }
        target_fn = target_map.get(engine_type, self._simulation_capture_loop)

        self._thread = threading.Thread(
            target=target_fn,
            name=f"PacketSnifferThread-{self.active_mode}",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"PacketSniffer started in [{self.active_mode}] mode (Interface: {self.interface or 'default'}).")

    def stop(self, timeout: float = 0.5) -> None:
        """Stop packet capture thread."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        with self._lock:
            self.stats["stop_time"] = time.time()

        logger.info("PacketSniffer stopped.")

    def is_running(self) -> bool:
        """Check if packet capture is currently active."""
        return self._running and (self._thread is not None and self._thread.is_alive())

    def get_packet(self, block: bool = True, timeout: Optional[float] = 1.0) -> Optional[Dict[str, Any]]:
        """Retrieve a single captured packet dict from the queue."""
        try:
            return self.packet_queue.get(block=block, timeout=timeout)
        except Empty:
            return None

    def get_all_packets(self) -> List[Dict[str, Any]]:
        """Drain and return all current packets in the queue."""
        packets = []
        while not self.packet_queue.empty():
            try:
                packets.append(self.packet_queue.get_nowait())
            except Empty:
                break
        return packets

    def get_stats(self) -> Dict[str, Any]:
        """Return live statistics of captured packets."""
        with self._lock:
            current_time = time.time()
            start = self.stats["start_time"] or current_time
            stop = self.stats["stop_time"] or current_time
            duration = max(stop - start, 0.001)

            total_pkts = self.stats["total_packets"]
            total_bytes = self.stats["total_bytes"]

            return {
                "capture_mode": self.active_mode,
                "interface": self.interface or "Auto/Default",
                "is_running": self.is_running(),
                "error_message": self.error_message,
                "total_packets": total_pkts,
                "tcp_count": self.stats["tcp_count"],
                "udp_count": self.stats["udp_count"],
                "icmp_count": self.stats["icmp_count"],
                "other_count": self.stats["other_count"],
                "total_bytes": total_bytes,
                "duration_seconds": round(duration, 2),
                "packets_per_second": round(total_pkts / duration, 2),
                "bytes_per_second": round(total_bytes / duration, 2),
            }

    def _process_packet_dict(self, pkt: Dict[str, Any]) -> None:
        """Filter, update statistics, queue, and execute callbacks for packet."""
        proto = pkt.get("protocol", "OTHER")

        # Protocol filtering
        if self.filter_proto and proto != self.filter_proto:
            return

        # Update Stats
        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += pkt.get("length", 0)

            if proto == "TCP":
                self.stats["tcp_count"] += 1
            elif proto == "UDP":
                self.stats["udp_count"] += 1
            elif proto == "ICMP":
                self.stats["icmp_count"] += 1
            else:
                self.stats["other_count"] += 1

        # Push to Queue (drop oldest if full)
        if self.packet_queue.full():
            try:
                self.packet_queue.get_nowait()
            except Empty:
                pass
        self.packet_queue.put(pkt)

        # Trigger Callback if provided
        if self.callback:
            try:
                self.callback(pkt)
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")

    # -------------------------------------------------------------------------
    # Engine 1: Direct Npcap C-Types Capture Loop (High-Speed LIVE Mode)
    # -------------------------------------------------------------------------
    def _npcap_capture_loop(self) -> None:
        """
        High-throughput LIVE packet capture via Npcap wpcap.dll.
        Uses 32 MB kernel driver ring buffer and ~1.2µs fast struct header parsing.
        """
        handle = None
        dll = None
        try:
            dll = _load_wpcap_dll()
            if not dll:
                raise RuntimeError("Npcap wpcap.dll could not be loaded.")

            errbuf = create_string_buffer(256)
            devs = POINTER(_pcap_if)()

            if dll.pcap_findalldevs(byref(devs), errbuf) != 0:
                raise RuntimeError(f"Failed to enumerate Npcap devices: {errbuf.value.decode('utf-8')}")

            target_dev = None
            target_desc = ""
            curr = devs

            # Match requested interface
            req_iface = (self.interface or "").lower().strip()
            while curr:
                dev = curr.contents
                desc = dev.description.decode('utf-8', errors='ignore') if dev.description else ''
                name = dev.name.decode('utf-8', errors='ignore') if dev.name else ''

                if req_iface and req_iface not in ("auto", "none", "default"):
                    if req_iface in name.lower() or req_iface in desc.lower():
                        target_dev = dev.name
                        target_desc = desc
                        break
                else:
                    # Auto: pick active Wi-Fi or Ethernet
                    if any(k in desc.lower() for k in ['wi-fi', 'wireless', 'wlan', 'ethernet']) and 'virtual' not in desc.lower():
                        target_dev = dev.name
                        target_desc = desc
                        break

                curr = dev.next

            # Fallback to first non-loopback device if no match
            if not target_dev:
                curr = devs
                while curr:
                    if b'Loopback' not in curr.contents.name:
                        target_dev = curr.contents.name
                        target_desc = curr.contents.description.decode('utf-8', errors='ignore') if curr.contents.description else ''
                        break
                    curr = curr.contents.next

            dev_bytes = target_dev
            dll.pcap_freealldevs(devs)

            if not dev_bytes:
                raise RuntimeError("No suitable Npcap network interface found.")

            # Open live device (snaplen = 65535, promisc = 1, timeout = 50ms)
            handle = dll.pcap_open_live(dev_bytes, 65535, 1, 50, errbuf)
            if not handle:
                raise RuntimeError(f"Failed to open Npcap device ({target_desc}): {errbuf.value.decode('utf-8')}")

            # Configure 32 MB kernel ring buffer
            dll.pcap_setbuff(handle, 32 * 1024 * 1024)
            logger.info(f"Npcap capture active on [{target_desc}] with 32MB kernel buffer.")

            hdr_ptr = c_void_p()
            data_ptr = POINTER(c_ubyte)()

            while not self._stop_event.is_set():
                res = dll.pcap_next_ex(handle, byref(hdr_ptr), byref(data_ptr))
                if res != 1:
                    continue  # Timeout or empty

                raw_hdr = string_at(hdr_ptr, 16)
                t_sec, t_usec, caplen, orig_len = struct.unpack('<iiII', raw_hdr)
                ts = t_sec + (t_usec / 1e6)
                raw_data = string_at(data_ptr, caplen)

                if len(raw_data) < 14:
                    continue

                # 1. Ethernet Header (14 bytes)
                eth_type = struct.unpack_from('>H', raw_data, 12)[0]
                offset = 14
                if eth_type == 0x8100:  # 802.1Q VLAN Tag
                    if len(raw_data) < 18:
                        continue
                    eth_type = struct.unpack_from('>H', raw_data, 16)[0]
                    offset = 18

                src_ip = None
                dst_ip = None
                proto_str = "OTHER"
                proto_num = 0
                src_port = 0
                dst_port = 0
                hdr_len = 0
                ttl = 64
                flags_dict = None
                window_size = 0

                if eth_type == 0x0800:  # IPv4
                    if len(raw_data) < offset + 20:
                        continue
                    v_ihl, tos, total_len, _, _, ttl, proto_num = struct.unpack_from('>BBHHHBB', raw_data, offset)
                    ihl = (v_ihl & 0x0F) * 4
                    if ihl < 20 or len(raw_data) < offset + ihl:
                        continue

                    src_ip = socket.inet_ntoa(raw_data[offset + 12 : offset + 16])
                    dst_ip = socket.inet_ntoa(raw_data[offset + 16 : offset + 20])
                    l4_offset = offset + ihl

                    if proto_num == 6:  # TCP
                        proto_str = "TCP"
                        if len(raw_data) >= l4_offset + 20:
                            sp, dp, seq, ack_seq, off_res, flg, win = struct.unpack_from('>HHIIBBH', raw_data, l4_offset)
                            src_port, dst_port = sp, dp
                            hdr_len = ((off_res >> 4) & 0x0F) * 4
                            window_size = win
                            flags_dict = {
                                "FIN": bool(flg & 0x01),
                                "SYN": bool(flg & 0x02),
                                "RST": bool(flg & 0x04),
                                "PSH": bool(flg & 0x08),
                                "ACK": bool(flg & 0x10),
                                "URG": bool(flg & 0x20),
                                "ECE": bool(flg & 0x40),
                                "CWE": bool(flg & 0x80),
                            }
                    elif proto_num == 17:  # UDP
                        proto_str = "UDP"
                        if len(raw_data) >= l4_offset + 8:
                            src_port, dst_port, _ = struct.unpack_from('>HHH', raw_data, l4_offset)
                            hdr_len = 8
                    elif proto_num == 1:  # ICMP
                        proto_str = "ICMP"
                        hdr_len = 8

                elif eth_type == 0x86DD:  # IPv6
                    if len(raw_data) < offset + 40:
                        continue
                    next_hdr = struct.unpack_from('>B', raw_data, offset + 6)[0]
                    proto_num = next_hdr
                    src_ip = socket.inet_ntop(socket.AF_INET6, raw_data[offset + 8 : offset + 24])
                    dst_ip = socket.inet_ntop(socket.AF_INET6, raw_data[offset + 24 : offset + 40])
                    l4_offset = offset + 40

                    if next_hdr == 6:  # TCP
                        proto_str = "TCP"
                        if len(raw_data) >= l4_offset + 20:
                            sp, dp, seq, ack_seq, off_res, flg, win = struct.unpack_from('>HHIIBBH', raw_data, l4_offset)
                            src_port, dst_port = sp, dp
                            hdr_len = ((off_res >> 4) & 0x0F) * 4
                            window_size = win
                            flags_dict = {
                                "FIN": bool(flg & 0x01),
                                "SYN": bool(flg & 0x02),
                                "RST": bool(flg & 0x04),
                                "PSH": bool(flg & 0x08),
                                "ACK": bool(flg & 0x10),
                                "URG": bool(flg & 0x20),
                                "ECE": bool(flg & 0x40),
                                "CWE": bool(flg & 0x80),
                            }
                    elif next_hdr == 17:  # UDP
                        proto_str = "UDP"
                        if len(raw_data) >= l4_offset + 8:
                            src_port, dst_port = struct.unpack_from('>HH', raw_data, l4_offset)
                            hdr_len = 8

                if not src_ip or not dst_ip:
                    continue

                pkt_dict = {
                    "timestamp": ts,
                    "timestamp_str": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto_str,
                    "protocol_num": proto_num,
                    "length": orig_len,
                    "header_len": hdr_len,
                    "ttl": ttl,
                    "tcp_flags": flags_dict,
                    "init_win": window_size,
                    "simulated": False,
                }

                self._process_packet_dict(pkt_dict)

        except Exception as e:
            err_msg = f"LIVE Npcap ctypes capture error on interface '{self.interface or 'default'}': {e}"
            logger.error(err_msg)
            self.error_message = err_msg
            self._running = False
        finally:
            if handle and dll:
                try:
                    dll.pcap_close(handle)
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Engine 2: Scapy Capture Loop (Legacy LIVE Mode)
    # -------------------------------------------------------------------------
    def _scapy_capture_loop(self) -> None:
        try:
            import scapy.all as scapy

            def scapy_callback(scapy_pkt):
                if not self._running:
                    return

                # Accept both IPv4 and IPv6 packets
                if scapy_pkt.haslayer(scapy.IP):
                    ip_layer = scapy_pkt[scapy.IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto_num = ip_layer.proto
                    ttl = getattr(ip_layer, "ttl", 64)
                    header_len = ip_layer.ihl * 4 if hasattr(ip_layer, "ihl") else 20
                elif scapy_pkt.haslayer(scapy.IPv6):
                    ip6_layer = scapy_pkt[scapy.IPv6]
                    src_ip = ip6_layer.src
                    dst_ip = ip6_layer.dst
                    proto_num = ip6_layer.nh  # Next Header field
                    ttl = getattr(ip6_layer, "hlim", 64)  # Hop Limit
                    header_len = 40  # Fixed IPv6 header size
                else:
                    return  # Not IP or IPv6 — skip

                proto_name = get_protocol_name(proto_num)

                src_port = 0
                dst_port = 0
                tcp_flags = None

                if scapy_pkt.haslayer(scapy.TCP):
                    tcp_layer = scapy_pkt[scapy.TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    tcp_flags = {
                        "FIN": "F" in tcp_layer.flags,
                        "SYN": "S" in tcp_layer.flags,
                        "RST": "R" in tcp_layer.flags,
                        "PSH": "P" in tcp_layer.flags,
                        "ACK": "A" in tcp_layer.flags,
                        "URG": "U" in tcp_layer.flags,
                    }
                elif scapy_pkt.haslayer(scapy.UDP):
                    udp_layer = scapy_pkt[scapy.UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport

                now = time.time()
                pkt_dict = {
                    "timestamp": now,
                    "timestamp_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto_name,
                    "protocol_num": proto_num,
                    "length": len(scapy_pkt),
                    "header_len": header_len,
                    "ttl": ttl,
                    "tcp_flags": tcp_flags,
                    "raw_bytes": bytes(scapy_pkt),
                    "simulated": False,
                }

                self._process_packet_dict(pkt_dict)

            # Start sniffing loop
            sniff_kwargs = {
                "prn": scapy_callback,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "store": 0,
            }
            if self.interface:
                sniff_kwargs["iface"] = self.interface

            scapy.sniff(**sniff_kwargs)
        except Exception as e:
            err_msg = f"LIVE Scapy capture error on interface '{self.interface or 'default'}': {e}"
            logger.error(err_msg)
            self.error_message = err_msg
            self._running = False
            # DO NOT fall back silently to simulation mode! Raise error / stop.

    # -------------------------------------------------------------------------
    # Engine 2: Raw Socket Capture Loop
    # -------------------------------------------------------------------------
    def _raw_socket_capture_loop(self) -> None:
        try:
            host_ip = self.interface or socket.gethostbyname(socket.gethostname())
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host_ip, 0))
            s.settimeout(0.5)

            if sys.platform == "win32":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while not self._stop_event.is_set():
                try:
                    raw_data, _ = s.recvfrom(65535)
                except socket.timeout:
                    continue

                ip_info = parse_ip_header(raw_data)
                if not ip_info:
                    continue

                transport_info = parse_transport_header(ip_info["protocol"], ip_info["payload"])
                now = time.time()

                pkt_dict = {
                    "timestamp": now,
                    "timestamp_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "src_ip": ip_info["src_ip"],
                    "dst_ip": ip_info["dst_ip"],
                    "src_port": transport_info["src_port"],
                    "dst_port": transport_info["dst_port"],
                    "protocol": ip_info["protocol"],
                    "protocol_num": ip_info["protocol_num"],
                    "length": len(raw_data),
                    "header_len": ip_info["ihl"],
                    "ttl": ip_info["ttl"],
                    "tcp_flags": transport_info["tcp_flags"],
                    "raw_bytes": raw_data,
                    "simulated": False,
                }
                self._process_packet_dict(pkt_dict)

            if sys.platform == "win32":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception as e:
            err_msg = f"LIVE Raw socket capture error: {e}"
            logger.error(err_msg)
            self.error_message = err_msg
            self._running = False
            # DO NOT fall back silently to simulation mode!

    # -------------------------------------------------------------------------
    # Engine 3: Simulation Capture Loop (Explicit SIMULATION Mode)
    # -------------------------------------------------------------------------
    def _simulation_capture_loop(self) -> None:
        """Generates synthetic traffic streams with multi-packet flow sessions."""
        normal_sessions = [
            ("192.168.1.45", 54320, "142.250.190.46", 443, "TCP"),
            ("192.168.1.45", 54322, "8.8.8.8", 53, "UDP"),
            ("192.168.1.102", 49152, "104.16.249.249", 80, "TCP"),
            ("10.0.0.15", 58900, "1.1.1.1", 443, "TCP"),
        ]

        active_sim_sessions = list(normal_sessions)

        while not self._stop_event.is_set():
            # Pick a sustained session or create a new one
            if random.random() < 0.20 or not active_sim_sessions:
                src_ip = random.choice(["192.168.1.45", "192.168.1.102", "10.0.0.15"])
                dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "142.250.190.46", "104.16.249.249"])
                proto = random.choice(["TCP", "TCP", "UDP", "ICMP"])
                src_port = random.randint(1024, 65535) if proto != "ICMP" else 0
                dst_port = random.choice([80, 443, 53, 8080]) if proto != "ICMP" else 0
                session = (src_ip, src_port, dst_ip, dst_port, proto)
                active_sim_sessions.append(session)
                if len(active_sim_sessions) > 10:
                    active_sim_sessions.pop(0)

            session = random.choice(active_sim_sessions)
            src_ip, src_port, dst_ip, dst_port, proto = session

            length = random.randint(128, 1460) if proto != "ICMP" else 64

            # Bi-directional packet simulation
            if random.random() < 0.4:
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port

            tcp_flags = None
            if proto == "TCP":
                tcp_flags = {
                    "FIN": False,
                    "SYN": False,
                    "RST": False,
                    "PSH": random.random() < 0.3,
                    "ACK": True,
                    "URG": False,
                }

            now = time.time()
            pkt_dict = {
                "timestamp": now,
                "timestamp_str": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "protocol_num": 6 if proto == "TCP" else (17 if proto == "UDP" else 1),
                "length": length,
                "header_len": 20,
                "ttl": 64,
                "tcp_flags": tcp_flags,
                "simulated": True,
            }

            self._process_packet_dict(pkt_dict)
            if self._stop_event.wait(timeout=random.uniform(0.01, 0.05)):
                break

