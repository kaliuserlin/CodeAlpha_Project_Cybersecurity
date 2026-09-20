# Task 4: Network Intrusion Detection System (NIDS)

This project implements a NIDS two ways, so you can demo both the
industry-standard tool (Suricata) and a fully custom engine you built
yourself and can explain line by line:

1. **Suricata** (industry-standard IDS) with custom detection rules
2. **`python_nids.py`** — a lightweight, from-scratch Python IDS using `scapy`

## Part A: Suricata Setup

### 1. Install Suricata
```bash
sudo apt update
sudo apt install suricata -y
```

### 2. Add the custom rules
Copy `suricata_rules/local.rules` into Suricata's rules directory:
```bash
sudo cp suricata_rules/local.rules /etc/suricata/rules/local.rules
```

Edit `/etc/suricata/suricata.yaml` and make sure `local.rules` is listed
under `rule-files:`:
```yaml
rule-files:
  - local.rules
```

### 3. Run Suricata in IDS (monitoring) mode
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```
(Replace `eth0` with your VM's interface — check with `ip a`.)

### 4. Monitor alerts
Suricata logs alerts to `/var/log/suricata/fast.log` (human-readable)
and `/var/log/suricata/eve.json` (structured JSON):
```bash
tail -f /var/log/suricata/fast.log
```

### 5. Generate test traffic to trigger alerts
From another machine/VM on the same network:
```bash
ping <target-ip> -c 20          # triggers ICMP ping sweep rule
nmap -sS <target-ip>            # triggers port scan rule
```

### 6. Visualize alerts (optional)
```bash
pip install matplotlib --break-system-packages
python3 visualize_alerts.py --source suricata --path /var/log/suricata/eve.json
```
This produces `alerts_dashboard.png` showing alert counts by category.

## Part B: Custom Python NIDS (`python_nids.py`)

Since Suricata's detection logic is pre-built and configured (not
written by you), this script is a from-scratch detection engine so you
fully understand and can explain the mechanics behind port scan
detection, flood detection, and signature matching.

### Detects
- **Port scans** — many distinct destination ports from one source IP in a short window
- **SYN floods** — high volume of unfinished TCP handshakes
- **ICMP floods** — ping-flood style DoS attempts
- **Suspicious payloads** — basic signature matching (SQLi, XSS, path traversal patterns)

### Response mechanism
Every alert is logged with a timestamp and severity to `alerts.log`.
Optionally, pass `--block` to automatically drop traffic from offending
IPs using `iptables` — this satisfies the "implement response
mechanisms" requirement.

### Run it
```bash
pip install scapy --break-system-packages

# Alert-only mode
sudo python3 python_nids.py -i eth0

# Alert + auto-block mode
sudo python3 python_nids.py -i eth0 --block
```

### Test it
```bash
# Trigger port scan detection
nmap -sT <your-vm-ip>

# Trigger ICMP flood detection
ping <your-vm-ip> -f -c 100      # requires root on the sending side

# Trigger SYN flood detection (use hping3 if available)
sudo hping3 -S -p 80 --flood <your-vm-ip>
```

### Visualize custom alerts
```bash
python3 visualize_alerts.py --source custom --path alerts.log
```

## Legal / Ethical Note
Only run detection or test-traffic generation (nmap, hping3, ping
floods) against machines/networks you own or have explicit permission
to test — ideally two VMs on the same isolated virtual network. Never
run these against systems you don't control.

## Learning Outcomes
- How signature-based and threshold-based (anomaly) detection works
- How real-world IDS tools like Suricata are configured and rule-based
- How to build detection logic (sliding time windows, thresholds) from scratch
- How automated response mechanisms (blocking via iptables) fit into an IDS pipeline
- How to summarize security events visually for a SOC-style dashboard
