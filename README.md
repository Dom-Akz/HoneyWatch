# 🍯 HoneyWatch — Intelligent Distributed Honeypot

> Real-time SSH attack detection, IOC collection, and threat visualization powered by a Cowrie honeypot and a Random Forest ML model.

**Author:** Soufiane Moussaoui — EMSI 4CIRA  
**Supervisor:** Prof. Khalid EL KHADIRI  
**Academic Year:** 2025/2026

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Part 1 — Ubuntu VM: Deploy the Cowrie Honeypot](#part-1--ubuntu-vm-deploy-the-cowrie-honeypot)
- [Part 2 — Server Machine: Install & Configure HoneyWatch](#part-2--server-machine-install--configure-honeywatch)
- [Part 3 — Train the ML Model](#part-3--train-the-ml-model)
- [Part 4 — Run the Application](#part-4--run-the-application)
- [Dashboard Features](#dashboard-features)
- [Project Structure](#project-structure)
- [Security Notice](#security-notice)

---

## Overview

HoneyWatch is a full-stack cybersecurity project that:

1. **Deploys a Cowrie SSH honeypot** on an Ubuntu VM to lure and log brute-force attackers
2. **Forwards honeypot logs** from the VM to the server machine via SSH
3. **Trains a Random Forest classifier** on extracted network traffic features to detect DDoS/attack patterns
4. **Streams live alerts** to a web dashboard with real-time charts, IOC export, and PDF report generation

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         Server Machine (Arch / any OS)      │
│                                             │
│  ┌──────────────┐    ┌────────────────────┐ │
│  │  Flask API   │───▶│  ML Detection      │ │
│  │  (server.py) │    │  (Random Forest)   │ │
│  └──────┬───────┘    └────────────────────┘ │
│         │ SSE stream                        │
│  ┌──────▼───────┐    ┌────────────────────┐ │
│  │  Frontend    │    │  cowrie_to_traffic  │ │
│  │  Dashboard   │    │  .py  (forwarder)  │ │
│  └──────────────┘    └────────┬───────────┘ │
└─────────────────────────────-─┼─────────────┘
                                │ SSH (tail logs)
┌───────────────────────────────▼─────────────┐
│            Ubuntu VM (Victim)               │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │   Cowrie Honeypot (Docker)          │    │
│  │   Port 2222 — SSH/Telnet lure       │    │
│  │   Logs → cowrie.json                │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

**Tech stack:**

| Component | Technology |
|---|---|
| Honeypot | Cowrie (medium-interaction SSH/Telnet) |
| Containerization | Docker + docker-compose |
| Victim VM | Ubuntu 22.04 |
| Server / Controller | Arch Linux (or any Linux/macOS) |
| Backend | Python 3.11 + Flask |
| ML Detection | scikit-learn Random Forest |
| Frontend Dashboard | HTML / CSS / JavaScript (Chart.js) |
| Log Forwarding | SSH + `cowrie_to_traffic.py` |
| Alert Storage | JSONL (`data/alerts.jsonl`) |

---

## Prerequisites

### Server machine

- Python 3.10+
- `pip` + `venv`
- SSH key pair with passwordless access to the Ubuntu VM
- Network access to the Ubuntu VM

### Ubuntu VM

- Docker + docker-compose installed
- Port 2222 open in the firewall
- SSH server running (for log forwarding from the server machine)

---

## Part 1 — Ubuntu VM: Deploy the Cowrie Honeypot

> Run all commands below **on the Ubuntu VM**.

### 1.1 Install Docker

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

### 1.2 Create the Cowrie directory and docker-compose file

```bash
mkdir -p ~/honeypot/logs
cd ~/honeypot
```

Create `docker-compose.yml`:

```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: always
    ports:
      - "2222:2222"
    privileged: true
    volumes:
      - ./logs:/cowrie/cowrie-git/var/log/cowrie
```

### 1.3 Start the honeypot

```bash
cd ~/honeypot
docker-compose up -d
```

Verify it is running:

```bash
docker ps
# You should see the 'cowrie' container listening on port 2222
```

### 1.4 Verify logs are being written

After a few minutes (or after triggering a test SSH connection), check:

```bash
tail -f ~/honeypot/logs/cowrie.json
```

You should see JSON entries like `cowrie.session.connect` and `cowrie.login.failed`.

### 1.5 Set up SSH key access from the server machine

On your **server machine**, generate a key (if you haven't already) and copy it to the VM:

```bash
ssh-keygen -t ed25519 -C "honeywatch"
ssh-copy-id vboxuser@<UBUNTU_VM_IP>
# Test it
ssh vboxuser@<UBUNTU_VM_IP> echo "OK"
```

---

## Part 2 — Server Machine: Install & Configure HoneyWatch

> Run all commands below **on your server machine**.

### 2.1 Clone / place the project

```
HoneyWatch/
├── backend/
│   ├── server.py
│   ├── detect_live.py
│   ├── train_model.py
│   ├── features.py
│   ├── capture.py
│   ├── cowrie_to_traffic.py
│   └── traffic_gen_http.py / traffic_gen_udp_tcp.py
├── frontend/
│   ├── index.html
│   └── script.js
├── data/           ← created automatically
├── models/         ← created automatically
└── requirements.txt
```

### 2.2 Create and activate a Python virtual environment

```bash
cd HoneyWatch
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# On Windows: venv\Scripts\activate
```

### 2.3 Install dependencies

```bash
pip install -r requirements.txt
```

A minimal `requirements.txt` for this project:

```
flask
flask-cors
pandas
scikit-learn
joblib
scapy
requests
```

### 2.4 Configure the Cowrie log forwarder

Open `backend/cowrie_to_traffic.py` and edit the configuration block at the top:

```python
UBUNTU_VM_IP  = "192.168.1.8"       # ← your Ubuntu VM's IP address
UBUNTU_USER   = "vboxuser"           # ← your Ubuntu VM username
COWRIE_LOG_PATH = "~/honeypot/logs/cowrie.json"
```

### 2.5 Fetch logs and generate traffic data (first run)

```bash
# Fetch the last 100 Cowrie log entries and write alerts directly
python backend/cowrie_to_traffic.py --mode once --limit 100

# Or run it continuously (polls every 5 seconds)
python backend/cowrie_to_traffic.py --mode continuous --interval 5
```

This populates `data/alerts.jsonl` directly (bypassing the CSV pipeline) and also saves raw logs to `data/honeypot_attacks_<timestamp>.csv`.

---

## Part 3 — Train the ML Model

The model learns from network traffic features (packets, bytes, entropy, source IPs, protocol ratios, etc.) to distinguish normal traffic from attacks.

### 3.1 (Optional) Extract features from a PCAP or traffic CSV

If you have a raw traffic CSV (`data/traffic_log.csv`) from live capture or PCAP files:

```bash
# From a PCAP file — converts to CSV first via capture.py:
python backend/capture.py --pcap path/to/file.pcap

# Then extract windowed features:
python backend/features.py --input data/traffic_log.csv --out data/features.csv --window 5
```

### 3.2 Train the Random Forest model

```bash
python backend/train_model.py
# Or specify a custom data file:
python backend/train_model.py --file data/features.csv --save models/ddos_model.joblib
```

Expected output:

```
[*] Loaded N windows from data/features.csv
[*] Label distribution:  0: X   1: Y
[*] Evaluation:
              precision    recall  f1-score ...
[*] Model saved to models/ddos_model.joblib
```

The trained model is saved to `models/ddos_model.joblib` and is loaded automatically when the server starts.

---

## Part 4 — Run the Application

With the virtual environment active and the model trained:

```bash
source venv/bin/activate
python backend/server.py
```

You should see:

```
[server] Launching DDoS detector backend...
[*] Loading model from models/ddos_model.joblib
[server] Background DDoS detection started.
Serving web dashboard on http://127.0.0.1:8000
```

Open your browser at **http://127.0.0.1:8000/dashboard**.

To change the port:

```bash
PORT=9000 python backend/server.py
```

### Keeping the forwarder running alongside the server

In a separate terminal (with the venv active):

```bash
python backend/cowrie_to_traffic.py --mode continuous --interval 5
```

New Cowrie alerts will stream into the dashboard in real time via Server-Sent Events (SSE).

---

## Dashboard Features

| Feature | Description |
|---|---|
| **Live Alert Table** | Paginated table of all detection windows (attacked / normal) |
| **Attacks Timeline** | Chart showing attack frequency over the selected time range |
| **Top Sources Chart** | Bar chart of the most active attacker IPs |
| **Probability Distribution** | Donut chart grouping alerts by ML confidence level |
| **IOC Panel** | Lists malicious source IPs and high-confidence events |
| **Export IOCs** | Downloads a structured `honeypot-iocs-<date>.json` file |
| **PDF Report** | Opens a printable report with summary stats, top attackers, and high-probability alerts |
| **Clear Alerts** | Wipes all in-memory alerts (does not delete the JSONL file) |
| **Time Range Filter** | Filter the dashboard view to last 24h / 7d / 30d |

### Report contents (PDF)

The report generated by the **PDF Report** button includes:

- Summary statistics (total alerts, detected attacks, average confidence, unique sources)
- Table of malicious source IPs with per-IP attack count and average probability
- Table of high-probability alerts (>80%) with timestamp, packet count, and top source
- Model detection metrics (detection rate, average confidence)

---

## Project Structure

```
HoneyWatch/
├── backend/
│   ├── server.py              # Flask API + SSE streaming + launches detection thread
│   ├── detect_live.py         # Live packet sniffing + ML inference loop
│   ├── train_model.py         # Random Forest training script
│   ├── features.py            # Feature extraction from traffic CSV (windowed stats)
│   ├── capture.py             # Live packet capture / PCAP reader → traffic_log.csv
│   ├── cowrie_to_traffic.py   # SSH log forwarder: Ubuntu VM → alerts.jsonl
│   ├── traffic_gen_http.py    # Safe local HTTP traffic generator (testing)
│   └── traffic_gen_udp_tcp.py # Safe local UDP/TCP burst generator (testing)
├── frontend/
│   ├── index.html             # Dashboard HTML
│   └── script.js              # Charts, SSE client, IOC export, PDF report generator
├── data/
│   ├── alerts.jsonl           # Append-only alert log (streamed to dashboard)
│   ├── traffic_log.csv        # Raw captured packets
│   └── features.csv           # Windowed features for model training
├── models/
│   └── ddos_model.joblib      # Trained Random Forest model
└── requirements.txt
```

---

## Security Notice

> ⚠️ **Important:** Exposing a honeypot on the internet attracts real attackers. Always isolate the honeypot VM in a dedicated network segment. Do **not** store sensitive data on the VM. Monitor resource usage to prevent the honeypot from being used as a pivot point.

Additional hardening recommendations from the project:

- Block confirmed malicious IPs at the firewall level using the exported IOC list
- Enforce strong password policies and disable password-based SSH on production systems
- Enable Multi-Factor Authentication (MFA) on all exposed services
- Apply SSH rate limiting (e.g., `fail2ban` or `ufw` rate limit rules)
- Regularly rotate the SSH key used by the log forwarder

---

## References

- [Cowrie SSH/Telnet Honeypot](https://github.com/cowrie/cowrie)
- [scikit-learn RandomForestClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [Flask Web Framework](https://flask.palletsprojects.com)
- [OWASP — Honeypots and Deception](https://owasp.org/www-community/Honeypots)
- [CISA — Indicators of Compromise](https://www.cisa.gov/indicators-compromise)
- [Hydra Password Cracker](https://github.com/vanhauser-thc/thc-hydra)
