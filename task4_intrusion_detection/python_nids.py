#!/usr/bin/env python3
"""
Task 4: Network Intrusion Detection System (lightweight, custom)
------------------------------------------------------------------
A signature + threshold based NIDS built with scapy. This complements
the Suricata setup (see suricata_rules/ and README.md) by giving you a
fully custom, from-scratch detection engine you built and understand
end to end -- useful for explaining "how NIDS work internally" in a
viva/demo, since Suricata itself is a black box you only configure.

Detects:
    - Port scans        (many distinct destination ports from one source)
    - SYN floods         (many SYN packets without completed handshakes)
    - ICMP floods        (ping flood / DoS attempts)
    - Suspicious payloads (basic signature matching, e.g. SQLi patterns)

Response mechanism:
    - Logs every alert with timestamp + severity to alerts.log
    - Optional --block flag auto-blocks offending IPs via iptables

IMPORTANT: Only run this on a network you own or have explicit
permission to monitor.

Requirements:
    pip install scapy --break-system-packages

Usage:
    sudo python3 python_nids.py
    sudo python3 python_nids.py -i eth0
    sudo python3 python_nids.py --block        # actively block attackers (requires root)
"""

import argparse
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, ICMP, Raw

# ---------------------------------------------------------------------------
# Configuration / thresholds -- tune these for your environment
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15       # distinct ports from one IP
PORT_SCAN_WINDOW = 10          # seconds
SYN_FLOOD_THRESHOLD = 50       # SYN packets from one IP
SYN_FLOOD_WINDOW = 5           # seconds
ICMP_FLOOD_THRESHOLD = 30      # ICMP echo requests from one IP
ICMP_FLOOD_WINDOW = 5          # seconds

SUSPICIOUS_SIGNATURES = [
    b"union select", b"' or 1=1", b"<script>", b"/etc/passwd",
    b"cmd.exe", b"drop table", b"../../../",
]

ALERT_LOG = "alerts.log"

# ---------------------------------------------------------------------------
# State tracking (per source IP)
# ---------------------------------------------------------------------------
port_activity = defaultdict(lambda: deque())   # ip -> deque[(timestamp, port)]
syn_activity = defaultdict(lambda: deque())    # ip -> deque[timestamp]
icmp_activity = defaultdict(lambda: deque())   # ip -> deque[timestamp]
blocked_ips = set()

alert_counts = defaultdict(int)


def log_alert(severity, category, src_ip, detail, block=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{severity}] {category} | Source: {src_ip} | {detail}"
    print(f"\033[91m{line}\033[0m" if severity == "HIGH" else line)

    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")

    alert_counts[category] += 1

    if block and src_ip not in blocked_ips:
        block_ip(src_ip)


def block_ip(ip):
    """Response mechanism: block the offending IP using iptables."""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"  -> Blocked {ip} via iptables")
        with open(ALERT_LOG, "a") as f:
            f.write(f"  -> ACTION: Blocked {ip} via iptables\n")
    except Exception as e:
        print(f"  -> Failed to block {ip}: {e}")


def prune_old(dq, window):
    """Remove entries older than `window` seconds from the left of a deque."""
    now = time.time()
    while dq and now - dq[0][0] > window:
        dq.popleft()


def check_port_scan(src_ip, dport, block):
    now = time.time()
    dq = port_activity[src_ip]
    dq.append((now, dport))
    while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
        dq.popleft()

    distinct_ports = {p for _, p in dq}
    if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
        log_alert("HIGH", "PORT_SCAN", src_ip,
                  f"{len(distinct_ports)} distinct ports hit in {PORT_SCAN_WINDOW}s", block)
        dq.clear()  # avoid re-alerting every packet


def check_syn_flood(src_ip, flags, block):
    if flags != "S":  # only pure SYN, no ACK -> handshake not completed
        return
    now = time.time()
    dq = syn_activity[src_ip]
    dq.append(now)
    while dq and now - dq[0] > SYN_FLOOD_WINDOW:
        dq.popleft()

    if len(dq) >= SYN_FLOOD_THRESHOLD:
        log_alert("HIGH", "SYN_FLOOD", src_ip,
                  f"{len(dq)} SYN packets in {SYN_FLOOD_WINDOW}s", block)
        dq.clear()


def check_icmp_flood(src_ip, block):
    now = time.time()
    dq = icmp_activity[src_ip]
    dq.append(now)
    while dq and now - dq[0] > ICMP_FLOOD_WINDOW:
        dq.popleft()

    if len(dq) >= ICMP_FLOOD_THRESHOLD:
        log_alert("MEDIUM", "ICMP_FLOOD", src_ip,
                  f"{len(dq)} ICMP echo requests in {ICMP_FLOOD_WINDOW}s", block)
        dq.clear()


def check_payload_signatures(src_ip, packet, block):
    if Raw not in packet:
        return
    payload = bytes(packet[Raw].load).lower()
    for sig in SUSPICIOUS_SIGNATURES:
        if sig in payload:
            log_alert("HIGH", "SUSPICIOUS_PAYLOAD", src_ip,
                      f"Matched signature: {sig.decode(errors='ignore')}", block)
            break


def process_packet(packet, block):
    if IP not in packet:
        return
    src_ip = packet[IP].src

    if TCP in packet:
        check_port_scan(src_ip, packet[TCP].dport, block)
        check_syn_flood(src_ip, str(packet[TCP].flags), block)
        check_payload_signatures(src_ip, packet, block)
    elif ICMP in packet:
        if packet[ICMP].type == 8:  # echo request
            check_icmp_flood(src_ip, block)


def print_summary(signum=None, frame=None):
    print("\n" + "-" * 60)
    print("IDS stopped. Alert summary:")
    total = sum(alert_counts.values())
    for cat, count in alert_counts.items():
        print(f"  {cat:20} {count}")
    print(f"  {'TOTAL':20} {total}")
    print(f"\nFull alert log: {ALERT_LOG}")
    if blocked_ips:
        print(f"Blocked IPs: {', '.join(blocked_ips)}")


def main():
    import signal, sys

    parser = argparse.ArgumentParser(description="Task 4: Lightweight Python NIDS")
    parser.add_argument("-i", "--interface", default=None, help="Interface to monitor")
    parser.add_argument("--block", action="store_true",
                         help="Actively block detected attacker IPs via iptables (requires root)")
    args = parser.parse_args()

    def handle_exit(signum, frame):
        print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    print("=" * 60)
    print("  Lightweight Network Intrusion Detection System - Task 4")
    print("=" * 60)
    print(f"Interface     : {args.interface or 'default'}")
    print(f"Auto-block    : {'ENABLED' if args.block else 'disabled (alert-only)'}")
    print("Detecting: port scans, SYN floods, ICMP floods, payload signatures")
    print("Press Ctrl+C to stop.\n")

    sniff(
        iface=args.interface,
        prn=lambda pkt: process_packet(pkt, args.block),
        store=False,
    )


if __name__ == "__main__":
    main()
