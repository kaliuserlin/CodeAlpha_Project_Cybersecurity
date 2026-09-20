#!/usr/bin/env python3
"""
Task 1: Basic Network Sniffer
-------------------------------
Captures live network packets, parses their structure (IP/TCP/UDP/ICMP
headers), displays source/destination info and payload content, and
keeps a running protocol-count summary.

IMPORTANT: Only run this on a network you own or have explicit
permission to monitor (e.g. your home network or a lab VM). Capturing
traffic on networks you don't own or lack permission for is illegal
in most jurisdictions.

Requirements:
    pip install scapy --break-system-packages

Usage:
    sudo python3 packet_sniffer.py
    sudo python3 packet_sniffer.py -i eth0
    sudo python3 packet_sniffer.py -f "tcp port 80"
    sudo python3 packet_sniffer.py -c 100
"""

import argparse
import signal
import sys
from datetime import datetime
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Global counters for the end-of-run summary
stats = Counter()
LOG_FILE = "packet_log.txt"


def get_printable_payload(packet, max_len=64):
    """Extract raw payload bytes and render only printable ASCII characters."""
    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        printable = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:max_len]
        )
        suffix = "..." if len(raw_bytes) > max_len else ""
        return printable + suffix
    return ""


def process_packet(packet):
    """Callback invoked by scapy for every captured packet."""
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        proto = "TCP"
        sport, dport = packet[TCP].sport, packet[TCP].dport
        flags = packet[TCP].flags
        detail = f"Port {sport} -> {dport}  Flags={flags}"
    elif UDP in packet:
        proto = "UDP"
        sport, dport = packet[UDP].sport, packet[UDP].dport
        detail = f"Port {sport} -> {dport}"
    elif ICMP in packet:
        proto = "ICMP"
        detail = f"Type={packet[ICMP].type} Code={packet[ICMP].code}"
    else:
        proto = f"OTHER({packet[IP].proto})"
        detail = ""

    stats[proto] += 1
    payload = get_printable_payload(packet)

    line = f"[{timestamp}] {proto:6} {src_ip:15} -> {dst_ip:15} | {detail}"
    if payload:
        line += f"\n           Payload: {payload}"

    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def print_summary(signum=None, frame=None):
    """Print protocol breakdown on exit (Ctrl+C)."""
    print("\n" + "-" * 60)
    print("Capture stopped. Protocol summary:")
    total = sum(stats.values())
    for proto, count in stats.most_common():
        pct = (count / total * 100) if total else 0
        print(f"  {proto:8} {count:6}  ({pct:.1f}%)")
    print(f"  {'TOTAL':8} {total:6}")
    print(f"\nFull log saved to: {LOG_FILE}")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Task 1: Basic Network Sniffer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (e.g. eth0). Default: scapy auto-selects.")
    parser.add_argument("-f", "--filter", default=None,
                         help="BPF filter, e.g. 'tcp', 'udp', 'icmp', 'port 80'")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = unlimited)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, print_summary)

    print("=" * 60)
    print("  Basic Network Sniffer - Task 1")
    print("=" * 60)
    print(f"Interface : {args.interface or 'default'}")
    print(f"Filter    : {args.filter or 'none'}")
    print(f"Count     : {args.count or 'unlimited'}")
    print("Press Ctrl+C to stop and see summary.\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=process_packet,
        store=False,
        count=args.count,
    )

    # If count was set and sniff() finished naturally, still print summary
    print_summary()


if __name__ == "__main__":
    main()
