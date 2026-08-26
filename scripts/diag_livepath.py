"""
scripts/diag_livepath.py
========================
Read-only LIVE-PATH INSTRUMENTATION for the PortScan detection pipeline.

It counts how many scan SYNs survive each boundary:

  (1) captured by Npcap  ->  (2) parsed as TCP SYN  ->  (3) reach the flow table
      ->  (4) recognized as probes by ScanDetector  ->  (5) trigger a PortScan alert

This script does NOT modify the detector, engine, thresholds, or architecture.
It reuses the production PacketSniffer + DetectionEngine unchanged and only
*observes* them, so the numbers it prints are the real pipeline's numbers.

RUN AS ADMINISTRATOR — live Npcap capture and nmap's raw SYN scan both require it.

USAGE (from the repo root, project venv, in an ELEVATED terminal):

  # Reproduce the failing case: a SELF-scan on the physical Wi-Fi adapter.
  # Expect (1) SYN count == 0 -> the packets never cross this adapter.
  .venv\\Scripts\\python.exe scripts\\diag_livepath.py --iface "MediaTek Wi-Fi 6 MT7921" --run-nmap --target 192.168.0.103

  # Same self-scan but capture on the Npcap Loopback Adapter -> SYNs now appear.
  .venv\\Scripts\\python.exe scripts\\diag_livepath.py --iface "loopback" --run-nmap --target 192.168.0.103

  # The correct on-wire test: scan a DIFFERENT host you own -> full path fires.
  .venv\\Scripts\\python.exe scripts\\diag_livepath.py --iface "MediaTek Wi-Fi 6 MT7921" --run-nmap --target <another-device-you-own>

AUTHORIZED USE ONLY: scan only hosts you own or may lawfully test.
"""

import sys
import time
import shutil
import pathlib
import argparse
import threading
import subprocess
from collections import defaultdict, Counter

# Windows consoles default to cp1252; force UTF-8 so output prints cleanly.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packet_capture.sniffer import PacketSniffer          # noqa: E402
from backend.detection_engine import DetectionEngine      # noqa: E402

try:
    from config import settings as _cfg
    PORT_FANOUT = _cfg.SCAN_PORT_FANOUT_THRESHOLD
    HOST_FANOUT = _cfg.SCAN_HOST_FANOUT_THRESHOLD
except Exception:
    PORT_FANOUT, HOST_FANOUT = 15, 15


def _find_nmap():
    return shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"


def main():
    ap = argparse.ArgumentParser(description="Live-path instrumentation for PortScan detection.")
    ap.add_argument("--iface", required=True,
                    help='Capture interface substring, e.g. "MediaTek Wi-Fi 6 MT7921" or "loopback".')
    ap.add_argument("--target", default=None,
                    help="Host to scan (one you own). Defaults to this machine (self-scan demo).")
    ap.add_argument("--scanner", default=None,
                    help="Expected scanner src IP (optional; auto-derived from traffic otherwise).")
    ap.add_argument("--duration", type=int, default=30, help="Capture seconds (default 30).")
    ap.add_argument("--ports", default=None, help='nmap port spec, e.g. "1-1000" (default: nmap default).')
    ap.add_argument("--run-nmap", action="store_true", help="Launch nmap -sS against --target automatically.")
    args = ap.parse_args()

    engine = DetectionEngine(scan_detection=True)
    if engine.scan_detector is None:
        print("[!] scan detection is disabled in config; enable SCAN_DETECTION_ENABLED to test.")
        sys.exit(2)

    # ── Boundary counters (updated on the capture thread) ────────────────────
    lock = threading.Lock()
    c = {"captured": 0, "tcp": 0, "syn_no_ack": 0}
    syn_ports_by_src = defaultdict(set)   # src_ip -> {dst_port} for bare SYNs
    pairs = set()                         # (src_ip, dst_ip) for bare SYNs

    def on_pkt(pkt):
        with lock:
            c["captured"] += 1
            if pkt.get("protocol") == "TCP":
                c["tcp"] += 1
                fl = pkt.get("tcp_flags") or {}
                if fl.get("SYN") and not fl.get("ACK"):
                    c["syn_no_ack"] += 1
                    syn_ports_by_src[pkt.get("src_ip")].add(pkt.get("dst_port"))
                    pairs.add((pkt.get("src_ip"), pkt.get("dst_ip")))
        # Exact production flow-table update — same call the engine makes.
        engine.process_packet(pkt)

    # Collect whatever the real sampler Step-3 / XGBoost path emits.
    scan_alerts, ml_alerts = [], []

    def on_alert(r):
        bucket = scan_alerts if r.get("detector") == "heuristic-scan" else ml_alerts
        bucket.append((time.time(), r))

    engine.register_alert_listener(on_alert)

    sniffer = PacketSniffer(interface=args.iface, mode="LIVE", callback=on_pkt)
    try:
        sniffer.start()
    except Exception as e:
        print(f"[!] capture failed to start: {e}")
        sys.exit(2)

    time.sleep(1.0)
    if not sniffer.is_running():
        print(f"[!] capture is not running (need admin?). error: {sniffer.error_message}")
        sys.exit(2)
    print(f"[+] capturing on '{args.iface}' -> bound device reported as: {sniffer.interface}")
    print(f"[+] listening for {args.duration}s ...")

    scan_start = None
    nmap_proc = None
    if args.run_nmap:
        target = args.target or "192.168.0.103"
        cmd = [_find_nmap(), "-sS", "-T4"]
        if args.ports:
            cmd += ["-p", args.ports]
        cmd += [target]
        print(f"[+] launching: {' '.join(cmd)}")
        scan_start = time.time()
        try:
            nmap_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] could not launch nmap ({e}); run it yourself in another elevated terminal.")
    else:
        print(f"    In another elevated terminal, run:  nmap -sS {args.target or '<target-you-own>'}")

    # Run the REAL Step-3 aggregation on the production 5s cadence.
    deadline = time.time() + args.duration
    while time.time() < deadline:
        try:
            engine._sample_and_predict_flows()
        except Exception as e:
            print(f"[!] sampler cycle error: {e}")
        time.sleep(5.0)

    # Snapshot the flow table for boundary (3)/(4) BEFORE the final sweep.
    # (Lower bound: closed-port RSTs may flush some probe flows between ticks;
    #  the alert count in (8) is the authoritative detection signal.)
    with engine._extractor_lock:
        flows = list(engine.extractor.active_flows.values())
    probes = [f for f in flows if engine.scan_detector.is_probe(f)]
    probe_ports_by_src = defaultdict(set)
    for f in probes:
        probe_ports_by_src[f.src_ip].add(f.dst_port)

    sniffer.stop()
    try:
        engine._sample_and_predict_flows()   # final sweep, as production stop() does
    except Exception as e:
        print(f"[!] final sweep error: {e}")
    if nmap_proc:
        try:
            nmap_proc.wait(timeout=5)
        except Exception:
            nmap_proc.kill()

    # The scanner is the src that emitted the most distinct SYN dst ports.
    scanner = args.scanner
    if not scanner and syn_ports_by_src:
        scanner = max(syn_ports_by_src, key=lambda s: len(syn_ports_by_src[s]))

    print("\n" + "=" * 70)
    print("LIVE-PATH INSTRUMENTATION REPORT")
    print("=" * 70)
    print(f"  (1) packets captured total               : {c['captured']}")
    print(f"        of which TCP                        : {c['tcp']}")
    print(f"  (2) parsed as TCP SYN (no ACK)           : {c['syn_no_ack']}")
    print(f"  (3) probe flows present in flow table    : {len(probes)}  (snapshot, lower bound)")
    print(f"  (4) recognized as probes by ScanDetector : {len(probes)}")
    print(f"  (5) busiest SYN source (the 'scanner')   : {scanner or 'NONE observed'}")
    if scanner:
        dsts = sorted({d for (s, d) in pairs if s == scanner})
        wire_ports = len(syn_ports_by_src.get(scanner, set()))
        table_ports = len(probe_ports_by_src.get(scanner, set()))
        print(f"        dst host(s) from scanner          : {dsts}")
        print(f"  (6) distinct dst ports from scanner      : {wire_ports} on the wire, "
              f"{table_ports} as flow-table probes")
        reached = table_ports >= PORT_FANOUT or wire_ports >= PORT_FANOUT
        print(f"  (7) vertical fan-out threshold           : {PORT_FANOUT} ports -> "
              f"{'REACHED' if reached else 'NOT reached'}")
    else:
        print(f"  (6) distinct dst ports from scanner      : 0")
        print(f"  (7) vertical fan-out threshold           : {PORT_FANOUT} ports -> NOT reached (no probes)")
    print(f"  (8) PortScan (heuristic-scan) alerts     : {len(scan_alerts)}")
    print(f"      XGBoost flow predictions this window : {len(ml_alerts)}   "
          f"<- what --live labels 'ML-layer alerts'")
    if ml_alerts:
        classes = Counter(r["prediction"] for _, r in ml_alerts)
        confs = [r["confidence_pct"] for _, r in ml_alerts]
        print(f"        prediction classes                : {dict(classes)}")
        print(f"        confidence min/mean/max           : "
              f"{min(confs):.1f} / {sum(confs)/len(confs):.1f} / {max(confs):.1f} %")
        if scan_start is not None:
            before = sum(1 for t, _ in ml_alerts if t < scan_start)
            print(f"        timing vs scan                    : {before} before, "
                  f"{len(ml_alerts) - before} during/after")
    print("=" * 70)

    if c["syn_no_ack"] == 0:
        print("VERDICT: ZERO scan SYNs reached the capture layer. They vanish at BOUNDARY (1)")
        print("         — they never traverse the sniffed adapter. If --target is this host's")
        print("         own IP, the OS loops the packets back internally and only the Npcap")
        print("         Loopback Adapter can see them. Re-run with --iface loopback, or scan a")
        print("         DIFFERENT host you own so the SYNs actually cross the Wi-Fi adapter.")
    elif len(probes) == 0:
        print("VERDICT: SYNs were captured but formed no probe flows -> inspect parse/flow keying.")
    elif not scan_alerts:
        print("VERDICT: probe flows formed but the fan-out threshold was not reached -> see (6)/(7).")
    else:
        print("VERDICT: full path OK -> PortScan detected by the heuristic layer.")


if __name__ == "__main__":
    main()
