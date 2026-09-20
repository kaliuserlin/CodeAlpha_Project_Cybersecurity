#!/usr/bin/env python3
"""
Alert Visualizer (optional, for Task 4)
------------------------------------------
Parses Suricata's eve.json log (or the custom python_nids.py alerts.log)
and produces a simple bar chart showing alert counts by category.

Requirements:
    pip install matplotlib --break-system-packages

Usage:
    # For Suricata's JSON alert log:
    python3 visualize_alerts.py --source suricata --path /var/log/suricata/eve.json

    # For the custom python_nids.py alerts.log:
    python3 visualize_alerts.py --source custom --path alerts.log
"""

import argparse
import json
import re
from collections import Counter

import matplotlib
matplotlib.use("Agg")  # no display needed, just saves a PNG
import matplotlib.pyplot as plt


def parse_suricata_eve(path):
    counts = Counter()
    with open(path) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                sig = event["alert"]["signature"]
                counts[sig] += 1
    return counts


def parse_custom_log(path):
    counts = Counter()
    pattern = re.compile(r"\[(HIGH|MEDIUM|LOW)\]\s+(\w+)\s+\|")
    with open(path) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                counts[match.group(2)] += 1
    return counts


def plot_counts(counts, output="alerts_dashboard.png"):
    if not counts:
        print("No alerts found to plot.")
        return

    labels = list(counts.keys())
    values = list(counts.values())

    plt.figure(figsize=(10, 6))
    plt.barh(labels, values, color="crimson")
    plt.xlabel("Number of Alerts")
    plt.title("Intrusion Detection Alerts by Category")
    plt.tight_layout()
    plt.savefig(output)
    print(f"Dashboard saved to {output}")


def main():
    parser = argparse.ArgumentParser(description="Visualize IDS alerts")
    parser.add_argument("--source", choices=["suricata", "custom"], required=True)
    parser.add_argument("--path", required=True, help="Path to eve.json or alerts.log")
    parser.add_argument("--output", default="alerts_dashboard.png")
    args = parser.parse_args()

    if args.source == "suricata":
        counts = parse_suricata_eve(args.path)
    else:
        counts = parse_custom_log(args.path)

    print("Alert counts:", dict(counts))
    plot_counts(counts, args.output)


if __name__ == "__main__":
    main()
