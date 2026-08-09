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
import random
import logging
import threading
from queue import Queue, Empty
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

from packet_capture.utils import (
    parse_ip_header,
    parse_transport_header,
    format_packet_info,
    get_protocol_name,
)

# Logging Setup
logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Thread-safe packet sniffer supporting Scapy, Raw Socket, and Simulation modes.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        filter_proto: Optional[str] = None,
        mode: str = "auto",
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_queue_size: int = 1000,
    ):
        """
        Initialize PacketSniffer.

        :param interface: Network interface name or IP to capture on (None = auto)
        :param filter_proto: Protocol filter ('TCP', 'UDP', 'ICMP', or None for all)
        :param mode: Capture mode ('auto', 'scapy', 'raw_socket', 'simulation')
        :param callback: Optional function invoked on every captured packet dict
        :param max_queue_size: Max buffer capacity for internal packet queue
        """
        self.interface = interface
        self.filter_proto = filter_proto.upper() if filter_proto else None
        self.requested_mode = mode.lower()
        self.active_mode = "simulation"
        self.callback = callback
        self.max_queue_size = max_queue_size

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

    def _determine_mode(self) -> str:
        """Test and select the best available capture mode."""
        if self.requested_mode != "auto":
            return self.requested_mode

        # Test Scapy mode (check if pcap is present)
        try:
            import scapy.all as scapy
            if hasattr(scapy, "get_working_ifaces") and scapy.get_working_ifaces():
                return "scapy"
        except Exception:
            pass

        # Test Raw Socket mode
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.close()
            return "raw_socket"
        except Exception:
            pass

        # Default to Simulation mode if hardware capture is restricted
        return "simulation"

    def start(self) -> None:
        """Start packet capture in a background thread."""
        if self._running:
            logger.warning("PacketSniffer is already running.")
            return

        self.active_mode = self._determine_mode()
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
            "scapy": self._scapy_capture_loop,
            "raw_socket": self._raw_socket_capture_loop,
            "simulation": self._simulation_capture_loop,
        }
        target_fn = target_map.get(self.active_mode, self._simulation_capture_loop)

        self._thread = threading.Thread(
            target=target_fn,
            name=f"PacketSnifferThread-{self.active_mode}",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"PacketSniffer started in [{self.active_mode.upper()}] mode.")

    def stop(self, timeout: float = 2.0) -> None:
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
                "active_mode": self.active_mode,
                "is_running": self.is_running(),
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
    # Engine 1: Scapy Capture Loop
    # -------------------------------------------------------------------------
    def _scapy_capture_loop(self) -> None:
        try:
            import scapy.all as scapy

            def scapy_callback(scapy_pkt):
                if not self._running:
                    return

                if not scapy_pkt.haslayer(scapy.IP):
                    return

                ip_layer = scapy_pkt[scapy.IP]
                proto_name = get_protocol_name(ip_layer.proto)

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
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto_name,
                    "protocol_num": ip_layer.proto,
                    "length": len(scapy_pkt),
                    "header_len": ip_layer.ihl * 4 if hasattr(ip_layer, 'ihl') else 20,
                    "ttl": getattr(ip_layer, "ttl", 64),
                    "tcp_flags": tcp_flags,
                    "raw_bytes": bytes(scapy_pkt),
                }

                self._process_packet_dict(pkt_dict)

            # Start sniffing loop
            scapy.sniff(
                iface=self.interface,
                prn=scapy_callback,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=0,
            )
        except Exception as e:
            logger.error(f"Scapy capture error ({e}). Falling back to simulation.")
            self.active_mode = "simulation"
            self._simulation_capture_loop()

    # -------------------------------------------------------------------------
    # Engine 2: Raw Socket Capture Loop
    # -------------------------------------------------------------------------
    def _raw_socket_capture_loop(self) -> None:
        try:
            host_ip = self.interface or socket.gethostbyname(socket.gethostname())
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host_ip, 0))
            s.settimeout(0.5)

            # Enable promiscuous mode on Windows
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
                }
                self._process_packet_dict(pkt_dict)

            if sys.platform == "win32":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception as e:
            logger.error(f"Raw socket error ({e}). Falling back to simulation.")
            self.active_mode = "simulation"
            self._simulation_capture_loop()

    # -------------------------------------------------------------------------
    # Engine 3: Simulation Capture Loop (For offline testing / restricted environments)
    # -------------------------------------------------------------------------
    def _simulation_capture_loop(self) -> None:
        """Generates realistic live traffic streams (Normal & Attack scenarios)."""
        normal_src_ips = ["192.168.1.45", "192.168.1.102", "10.0.0.15", "172.16.0.8"]
        external_dst_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "104.16.249.249"]
        attacker_ips = ["185.220.101.5", "45.154.255.12", "192.168.1.250"]

        common_ports = [80, 443, 53, 22, 8080, 21, 3389, 445]

        while not self._stop_event.is_set():
            # 85% normal traffic, 15% simulated attack pattern (DoSS, PortScan, etc.)
            is_attack = random.random() < 0.15

            if not is_attack:
                proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
                src_ip = random.choice(normal_src_ips)
                dst_ip = random.choice(external_dst_ips)
            else:
                proto = random.choice(["TCP", "UDP", "TCP"])
                src_ip = random.choice(attacker_ips)
                dst_ip = "192.168.1.100"  # Target server

            src_port = random.randint(1024, 65535) if proto != "ICMP" else 0
            dst_port = random.choice(common_ports) if proto != "ICMP" else 0

            length = random.randint(64, 1514) if proto != "ICMP" else random.randint(64, 128)

            tcp_flags = None
            if proto == "TCP":
                tcp_flags = {
                    "FIN": random.random() < 0.1,
                    "SYN": is_attack or random.random() < 0.3,
                    "RST": random.random() < 0.05,
                    "PSH": random.random() < 0.4,
                    "ACK": random.random() < 0.8,
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
                "ttl": random.choice([64, 128, 255]),
                "tcp_flags": tcp_flags,
                "simulated": True,
            }

            self._process_packet_dict(pkt_dict)
            time.sleep(random.uniform(0.05, 0.2))  # ~5-20 packets/sec
