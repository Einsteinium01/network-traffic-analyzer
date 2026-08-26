"""
feature_extraction/scan_detector.py
====================================
WHY THIS FILE EXISTS
--------------------
The flow-level XGBoost model (Phase 2) is trained on CICIDS2017 flow records.
A rapid TCP port scan (e.g. ``nmap -sS``) produces MANY short-lived flows — one
per probed port — each holding only 1-2 packets (a lone SYN, or SYN + RST). Such
flows have degenerate features (zero duration, no inter-arrival time, no TCP
window size), and the model confidently classifies them as BENIGN. Feeding these
single-packet flows to the model would mean fabricating the missing CICIDS2017
feature semantics, so instead we detect the scan at the level it actually exists:
a single source fanning out across many destination ports/hosts in a short time.

HOW IT WORKS
------------
``ScanDetector`` is a pure, side-effect-free aggregator (aside from an internal
per-source cooldown clock). It is driven by the DetectionEngine's existing
5-second flow sampler — it is NOT called per packet:

1. ``is_probe(flow)`` decides whether a flow looks like an unestablished SYN
   probe (TCP, SYN seen, <= N packets, no PSH/FIN — i.e. no established data
   transfer or graceful teardown).
2. ``evaluate(flows, now)`` groups the probe flows by source IP and counts the
   distinct destination ports and distinct destination hosts each source hit.
   A source is flagged when it crosses the vertical (many ports on a host) or
   horizontal (one port across many hosts) fan-out threshold.
3. A per-source cooldown prevents a sustained scan from emitting an alert every
   sampler cycle.

This is a classic signature/heuristic layer running ALONGSIDE the ML anomaly
layer (hybrid IDS). It changes neither the 70-feature schema nor the model.

FILE: feature_extraction/scan_detector.py
"""

from typing import Any, Dict, Iterable, List


class ScanDetector:
    """Aggregates unestablished SYN probe flows into PortScan observations."""

    def __init__(
        self,
        port_fanout_threshold: int = 15,
        host_fanout_threshold: int = 15,
        max_probe_packets: int = 2,
        cooldown_seconds: float = 30.0,
    ):
        """
        :param port_fanout_threshold: distinct dst ports from one source that
            trigger a vertical-scan alert.
        :param host_fanout_threshold: distinct dst hosts from one source that
            trigger a horizontal-sweep alert.
        :param max_probe_packets: a flow with more packets than this is treated
            as an established connection, not a probe.
        :param cooldown_seconds: minimum gap between alerts for the same source.
        """
        self.port_fanout_threshold = int(port_fanout_threshold)
        self.host_fanout_threshold = int(host_fanout_threshold)
        self.max_probe_packets = int(max_probe_packets)
        self.cooldown_seconds = float(cooldown_seconds)

        # src_ip -> timestamp of the last alert we emitted for it.
        self._last_alerted: Dict[str, float] = {}

    # ── Probe classification ────────────────────────────────────────────────
    def is_probe(self, flow: Any) -> bool:
        """
        True if *flow* looks like an unestablished TCP SYN probe.

        A real TCP session completes a 3-way handshake and then carries data,
        so it exceeds ``max_probe_packets`` and sets PSH almost immediately.
        A scan probe is a lone SYN (optionally answered by a single RST/SYN-ACK)
        that never carries data and never gracefully closes (no FIN).

        Note: we deliberately do NOT rely on ``act_data_pkt_fwd`` here — in this
        pipeline packet ``length`` is the full frame while ``header_len`` is only
        the TCP header, so that counter over-reports payload for a bare SYN.
        Packet count + flag shape is the robust signal.
        """
        if getattr(flow, "protocol", None) != "TCP":
            return False
        flags = getattr(flow, "flag_counts", {})
        if flags.get("SYN", 0) < 1:
            return False
        total_pkts = flow.fwd_pkts + flow.bwd_pkts
        if total_pkts > self.max_probe_packets:
            return False
        # Any pushed data or graceful teardown means this was a real session.
        if flags.get("PSH", 0) > 0 or flags.get("FIN", 0) > 0:
            return False
        return True

    # ── Aggregation ─────────────────────────────────────────────────────────
    def evaluate(self, flows: Iterable[Any], now: float) -> List[Dict[str, Any]]:
        """
        Group probe flows by source IP and emit a PortScan detection for every
        source that crosses a fan-out threshold and is not in cooldown.

        :param flows: the flows currently visible to the sampler (active + just
            expired). Non-probe flows are ignored.
        :param now: current epoch seconds (passed in — the sampler owns the clock).
        :returns: a list of detection dicts (one per triggering source IP).
        """
        groups: Dict[str, Dict[str, Any]] = {}
        for flow in flows:
            if not self.is_probe(flow):
                continue
            g = groups.get(flow.src_ip)
            if g is None:
                g = {"ports": set(), "hosts": set(), "host_hits": {}, "count": 0}
                groups[flow.src_ip] = g
            g["ports"].add(flow.dst_port)
            g["hosts"].add(flow.dst_ip)
            g["host_hits"][flow.dst_ip] = g["host_hits"].get(flow.dst_ip, 0) + 1
            g["count"] += 1

        detections: List[Dict[str, Any]] = []
        for src_ip, g in groups.items():
            distinct_ports = len(g["ports"])
            distinct_hosts = len(g["hosts"])
            vertical = distinct_ports >= self.port_fanout_threshold
            horizontal = distinct_hosts >= self.host_fanout_threshold
            if not (vertical or horizontal):
                continue

            # Suppress repeat alerts for an ongoing scan.
            if now - self._last_alerted.get(src_ip, 0.0) < self.cooldown_seconds:
                continue
            self._last_alerted[src_ip] = now

            # Label by the dominant dimension; a source hitting many ports on one
            # host is vertical, many hosts on one port is a horizontal sweep.
            scan_type = "vertical" if distinct_ports >= distinct_hosts else "horizontal"
            attack_type = "PortScan (vertical)" if scan_type == "vertical" else "PortScan (host sweep)"

            # Most-targeted host is the representative destination for the UI.
            rep_host = max(g["host_hits"].items(), key=lambda kv: kv[1])[0]

            excess = max(
                distinct_ports - self.port_fanout_threshold,
                distinct_hosts - self.host_fanout_threshold,
                0,
            )
            confidence = min(0.99, 0.85 + 0.01 * excess)

            detections.append({
                "src_ip": src_ip,
                "dst_ip": rep_host,
                "dst_port": next(iter(g["ports"])) if distinct_ports == 1 else 0,
                "distinct_ports": distinct_ports,
                "distinct_hosts": distinct_hosts,
                "probe_count": g["count"],
                "confidence": confidence,
                "attack_type": attack_type,
                "scan_type": scan_type,
            })

        self._prune(now)
        return detections

    def reset(self) -> None:
        """Forget all cooldown state (call when monitoring restarts)."""
        self._last_alerted.clear()

    # ── Internal ──────────────────────────────────────────────────────────────
    def _prune(self, now: float) -> None:
        """Drop cooldown entries far past their window to bound memory."""
        horizon = self.cooldown_seconds * 4
        stale = [ip for ip, ts in self._last_alerted.items() if now - ts > horizon]
        for ip in stale:
            del self._last_alerted[ip]
