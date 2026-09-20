# Task 1: Basic Network Sniffer

A Python-based packet sniffer built with `scapy` that captures live network
traffic and displays packet structure, protocol information, and payload
content in real time.

## Features
- Captures live packets on any network interface
- Parses IP, TCP, UDP, and ICMP headers
- Displays source IP, destination IP, ports, and TCP flags
- Extracts and displays printable payload content
- Logs every packet to `packet_log.txt`
- Prints a protocol breakdown summary (TCP/UDP/ICMP counts) on exit
- Supports BPF filters (e.g. capture only TCP, or only port 80)

## Requirements
- Linux (recommended — VM or native)
- Python 3
- `scapy` library

```bash
pip install scapy --break-system-packages
```

## Usage

```bash
# Capture all traffic on the default interface
sudo python3 packet_sniffer.py

# Capture on a specific interface
sudo python3 packet_sniffer.py -i eth0

# Capture only TCP traffic
sudo python3 packet_sniffer.py -f tcp

# Capture only HTTP traffic (port 80), stop after 50 packets
sudo python3 packet_sniffer.py -f "port 80" -c 50
```

Root privileges (`sudo`) are required because raw packet capture needs
elevated permissions.

## How it works
1. `scapy.sniff()` captures raw packets from the network interface.
2. Each packet is passed to `process_packet()`, which checks for an IP
   layer, then identifies the transport-layer protocol (TCP/UDP/ICMP).
3. Relevant header fields (IPs, ports, flags) are extracted and printed.
4. If the packet carries a payload (`Raw` layer), printable ASCII bytes
   are extracted and shown alongside the header info.
5. On exit (Ctrl+C), a summary table shows how many packets of each
   protocol were captured.

## Sample Output
```
[14:32:10] TCP    192.168.1.5     -> 142.250.183.14  | Port 51322 -> 443  Flags=S
[14:32:10] UDP    192.168.1.5     -> 8.8.8.8         | Port 53211 -> 53
           Payload: ..google.com........
```

## Legal / Ethical Note
Only run this tool on a network you own or have explicit permission to
monitor (e.g. your home network or a personal lab VM). Capturing traffic
on networks without authorization is illegal in most jurisdictions.

## Learning Outcomes
- How data is structured and moves through network layers (IP/TCP/UDP/ICMP)
- How to use `scapy` for packet capture and analysis
- How real tools like Wireshark work under the hood
