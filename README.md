# NetGuard — Network Intrusion Detection System (NIDS)
### Enterprise Network Traffic Analyzer, Heuristic Threat Detector & SOC Dashboard

![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)
![Build Status](https://img.shields.io/badge/tests-111%20passed-success.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![Binding](https://img.shields.io/badge/binding-127.0.0.1%3A5000-orange.svg)

**NetGuard** is a modular, defensive Network Intrusion Detection System (NIDS) designed to ingest raw network traffic, extract high-dimensional protocol features, detect anomalous activity and volumetric flood patterns, compute heuristic risk scores, and present real-time telemetry through an interactive Security Operations Center (SOC) dashboard.

---

## 1. Problem Statement

Modern enterprise networks generate massive volumes of continuous packet data. Detecting reconnaissance scans, denial-of-service volumetric floods, and local spoofing attacks requires scalable ingestion, strict protocol normalization, and explainable detection logic. Many commercial systems act as black boxes with proprietary risk scores and complex cloud dependencies. NetGuard provides an educational, auditable, and self-contained defensive monitoring architecture that can operate either offline against stored PCAP captures or online via opt-in network packet sniffing.

---

## 2. Project Objectives

1. **Robust Ingestion**: Ingest and parse network frames from offline PCAP/PCAPNG files and live adapters via Scapy.
2. **Vectorized Analytics**: Calculate multi-variable traffic features (packet size percentiles, throughput rates, protocol breakdowns) using NumPy.
3. **Multi-Vector Detection**: Implement rule-based detection for Port Scans, SYN Floods, UDP Floods, ICMP Floods, ARP Anomalies, and Statistical Anomalies.
4. **Transparent Risk Scoring**: Compute auditable risk scores (0–100) based on deterministic base threat weights and empirical evidence modifiers.
5. **Thread-Safe Persistence**: Store traffic metadata, alerts, and host inventories in SQLite using parameterized batch transactions.
6. **Enterprise Web Dashboard**: Present real-time telemetry, historical trends, alert lifecycle management, and PCAP upload workflows via a dark-themed SOC interface.

---

## 3. Key Features

- **Dual-Mode Packet Ingestion**: Memory-efficient generator streaming for large offline PCAP files, and multi-threaded background sniffing for live network adapters.
- **Producer-Consumer Threading**: Decouples packet sniffing from analysis using a bounded queue (`maxsize=10,000`) with backpressure accounting for dropped packets.
- **NumPy Analytics**: Zero-copy array processing computing size distributions (mean, std, min, max, p25, p50, p95), transfer rates (PPS, BPS), and TCP flag metrics.
- **Six Rule Detectors**:
  - *TCP SYN Port Scan Detector*: Differentiates multi-port reconnaissance from single-port bursts.
  - *TCP SYN Flood Detector*: Identifies high-rate half-open connection attempts.
  - *UDP Volumetric Flood Detector*: Detects abnormal high-rate UDP streams.
  - *ICMP Echo Flood Detector*: Detects ping flood denial-of-service attempts.
  - *ARP Anomaly Detector*: Flags conflicting MAC addresses claiming existing IP mappings.
  - *Statistical Anomaly Detector*: Identifies burst spikes, packet size Z-score deviations ($Z \ge 3.0$), and concentrated source ratios.
- **Heuristic Risk Scorer**: Clamps scores between 0 and 100 (`np.clip`), mapping threats to CRITICAL, HIGH, MEDIUM, and LOW severity.
- **Alert Deduplication & Lifecycle**: Prevents alert flooding within configurable suppression windows and supports investigation states (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- **Enterprise SOC Dashboard**: Single-page application (SPA) featuring 8 operational views, 4 Chart.js visualizations, slideout alert dossiers, and drag-and-drop PCAP analysis.

---

## 4. Technology Stack

- **Core Backend**: Python 3.10 – 3.14
- **Packet Ingestion**: Scapy 2.5+ / 2.7+
- **Numerical Analytics**: NumPy 1.24+ / 2.x, Pandas 2.x / 3.x
- **Persistence**: SQLite3 (native standard library)
- **Web Application & REST API**: Flask 3.x, Werkzeug 3.x
- **Frontend Dashboard**: HTML5, Vanilla CSS3, Vanilla ES6+ JavaScript
- **Visualizations**: Chart.js 4.x (bundled locally for offline use)
- **Icons**: Lucide Icons (bundled locally for offline use)
- **Testing**: Pytest 7.x – 9.x

---

## 5. System Architecture Overview

```
 [Live Interface / PCAP] ──▶ [PacketParser] ──▶ [TrafficCleaner] ──▶ [NumPy Analyzer]
                                                                            │
 ┌──────────────────────────────────────────────────────────────────────────┘
 │
 ▼
[Detection Rule Engine] ──▶ [Risk Scorer] ──▶ [Alert Manager] ──▶ [SQLite DB]
 (PortScan, Floods, ARP,                       (Deduplication &    (traffic, alerts,
  Statistical Anomalies)                        Status Tracking)    stats, hosts)
                                                                        │
                                                                        ▼
                                                                [Flask REST API]
                                                                        │
                                                                        ▼
                                                               [SOC Web Dashboard]
```

For full sequence diagrams and thread lifecycle specifications, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 6. Directory Structure

```text
NetGuard/
│
├── main.py                     # CLI entry point & server orchestrator
├── config.py                   # Centralized configuration & thresholds
├── requirements.txt            # Python package dependencies
├── README.md                   # System documentation
│
├── capture/                    # Packet ingestion layer
│   ├── pcap_reader.py          # Chunked streaming PCAP/PCAPNG reader
│   ├── live_capture.py         # Scapy adapter sniffer & interface enumeration
│   └── monitor_manager.py      # Producer-consumer threading & queue orchestrator
│
├── preprocessing/              # Normalization & data structures
│   ├── packet_parser.py        # Standardized PacketRecord dataclass
│   └── traffic_cleaner.py      # Validation, normalization & sanitization
│
├── features/                   # Vectorized traffic analysis
│   ├── numpy_analyzer.py       # NumPy array math (sizes, rates, percentiles)
│   └── feature_extractor.py    # Pipeline coordinating summary statistics
│
├── detection/                  # Heuristic detection engines
│   ├── port_scan_detector.py   # Sliding window TCP port scan detector
│   ├── flood_detector.py       # SYN, UDP, and ICMP volumetric flood detector
│   ├── arp_detector.py         # IP-to-MAC association cache & anomaly detector
│   ├── anomaly_detector.py     # Burst, Z-score & source concentration detector
│   └── rule_engine.py          # Central detector coordinator & deduplicator
│
├── scoring/                    # Risk assessment
│   └── risk_scorer.py          # Heuristic base scoring & evidence modifiers
│
├── alerts/                     # Alert management
│   └── alert_manager.py        # Alert IDs, deduplication & status state machine
│
├── database/                   # Persistence layer
│   ├── schema.sql              # 4 indexed relational SQLite tables
│   └── db.py                   # Thread-safe parameterized SQLite repository
│
├── dashboard/                  # Web dashboard & REST API
│   ├── app.py                  # Flask application factory
│   ├── routes.py               # REST API blueprint (13 endpoints)
│   ├── templates/
│   │   └── index.html          # Semantic single-page SOC dashboard skeleton
│   └── static/
│       ├── css/                # Enterprise dark theme & responsive stylesheets
│       ├── js/                 # Modular ES6 controllers & Chart.js engine
│       └── vendor/             # Bundled offline Chart.js and Lucide assets
│
├── samples/                    # Sanitized sample PCAP files
│   ├── sample_test.pcap        # Benign mixed-protocol sample (10 pkts)
│   └── suspicious_sample.pcap  # Port scan + ARP anomaly test capture (22 pkts)
│
├── docs/                       # Technical specifications
│   ├── ARCHITECTURE.md         # Data flow diagrams & concurrency design
│   ├── API.md                  # Complete REST API reference
│   └── DEMO_GUIDE.md           # Step-by-step evaluation guide
│
└── testing/                    # Automated Pytest test suite (111 tests)
```

---

## 7. Installation Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.14
- Git
- (Optional, Windows Live Capture only) **Npcap** or WinPcap (select *"Install Npcap in WinPcap API-compatible Mode"*)

### Installation on Windows

```powershell
# 1. Clone repository
git clone https://github.com/your-username/NetGuard.git
cd NetGuard

# 2. Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Installation on Linux

```bash
# 1. Clone repository
git clone https://github.com/your-username/NetGuard.git
cd NetGuard

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# (Optional: Grant sniffer capabilities without running as full root)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

---

## 8. Usage & CLI Workflows

NetGuard provides a unified command-line interface via `main.py`.

### A. Offline PCAP Analysis
Analyze offline capture files without needing elevated administrative privileges:

```powershell
# Analyze default sample capture:
python main.py --sample

# Analyze specific capture file:
python main.py --pcap samples/suspicious_sample.pcap

# Limit packet processing ceiling:
python main.py --pcap path/to/large.pcap --max-packets 1000
```

### B. Database Inspection
Inspect records, alerts, and hosts stored in the local SQLite database (`netguard.db`):

```powershell
# View recent security alerts:
python main.py --alerts

# View active host inventory:
python main.py --hosts

# View database table counts:
python main.py --stats
```

### C. Live Network Monitoring (Opt-in)
Enumerate network adapters and start live background capture:

```powershell
# List available network adapters:
python main.py --interfaces

# Start live monitoring on default interface:
python main.py --monitor

# Start live monitoring on specific adapter with BPF filter:
python main.py --monitor --iface "Wi-Fi" --filter "tcp port 80"
```

> **Privilege Note**: On Windows, live network packet sniffing requires Administrator privileges and an active Npcap installation. If privileges are missing, NetGuard handles the permission error gracefully. Offline PCAP analysis never requires elevated privileges.

### D. Launch the SOC Web Dashboard
Start the local Flask REST API and web application:

```powershell
python main.py --server
```

Open your browser to:
```text
http://127.0.0.1:5000
```

---

## 9. REST API Endpoints

NetGuard binds exclusively to `127.0.0.1:5000` (localhost loopback):

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/status` | `GET` | System health, monitoring state, and record counts |
| `/api/interfaces` | `GET` | Enumerate host network interfaces |
| `/api/monitor/start` | `POST` | Start live background capture |
| `/api/monitor/stop` | `POST` | Stop live capture and flush buffer |
| `/api/monitor/status` | `GET` | Real-time packet throughput and queue metrics |
| `/api/statistics` | `GET` | Current network volume and protocol counts |
| `/api/statistics/history` | `GET` | Historical throughput metrics over time |
| `/api/traffic` | `GET` | Paginated packet records with protocol/IP filtering |
| `/api/alerts` | `GET` | Query security alerts with severity/threat filters |
| `/api/alerts/<id>` | `GET` | Full alert investigation dossier and evidence JSON |
| `/api/alerts/<id>/status`| `PATCH` | Update alert status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) |
| `/api/hosts` | `GET` | Query discovered hosts with search support |
| `/api/analyze/pcap` | `POST` | Upload PCAP/PCAPNG file for sandboxed analysis (Max 10 MB) |

For comprehensive payload examples and error responses, see [docs/API.md](docs/API.md).

---

## 10. Detection & Scoring Methodology

### Heuristic Risk Scoring
Risk scores are **heuristic numerical assessments** (0–100) reflecting relative threat severity and observable empirical factors:

$$\text{Risk Score} = \min\left(100,\; \max\left(0,\; \text{Base Score} + \sum \text{Modifiers}\right)\right)$$

| Threat Identifier | Base Score | Severity | Description |
| :--- | :---: | :---: | :--- |
| `SYN_FLOOD` | 90 | CRITICAL | Volumetric burst of TCP SYN-only packets exceeding 80 PPS |
| `ARP_ANOMALY` | 85 | CRITICAL | Conflicting MAC address claiming an existing mapped IP |
| `UDP_FLOOD` | 85 | CRITICAL | Volumetric UDP packet flood exceeding 100 PPS |
| `ICMP_FLOOD` | 75 | HIGH | Echo request flood exceeding 40 PPS |
| `PORT_SCAN` | 60 | HIGH | Probing $\ge 15$ unique target ports within 10 seconds |
| `STATISTICAL_ANOMALY` | 40 | MEDIUM | Extreme packet rate spike ($\ge 500$ PPS) or size Z-score outlier |

### Detection Semantics & Nuance:
- **Evidence Classification, Not Probability**: Alert confidence reflects observable protocol indicators (e.g., presence of TCP handshake responses vs. unanswered SYN probes), not a probabilistic prediction.
- **Attribution Discipline**: NetGuard references candidate traffic sources as **"Suspicious Source IP"** rather than declaring confirmed attacker identities.
- **ARP Anomaly Reality**: An unexpected MAC mapping change is an indicator of potential ARP spoofing; however, legitimate network events (DHCP lease reallocations, virtual machine migrations, or router failover) can also produce MAC changes.

---

## 11. Testing & Verification

NetGuard maintains an automated Pytest test suite covering all pipeline layers:

```powershell
# Run the complete test suite:
python -m pytest testing/ -v
```

### Test Coverage Summary (111 tests passing):
- `test_parser.py`: L2–L4 packet parsing, TCP flags, IPv6, synthetic PCAP streaming.
- `test_features.py`: Vectorized NumPy array mathematics, percentiles, transfer rates.
- `test_detection.py`: Rules for port scanning, floods, ARP flapping, and statistical anomalies.
- `test_scoring.py`: Clamping bounds, severity thresholds, and multi-indicator aggregation.
- `test_alerts.py`: Alert ID generation, deduplication windows, and state transitions.
- `test_database.py`: Schema migrations, batch transactions, UPSERTs, and SQL injection resistance.
- `test_live_capture.py`: Interface enumeration and Scapy sniffer lifecycle.
- `test_monitor_manager.py`: Producer-consumer queues, backpressure drops, and flush on shutdown.
- `test_api.py`: REST API endpoints, parameter validation, and status PATCHing.
- `test_audit_phase5.py`: PCAP magic byte verification, 10MB limits, and traversal neutralization.
- `test_dashboard_frontend.py`: HTML5 template delivery, view containers, and attribution wording.

---

## 12. Known Limitations & Operating Boundaries

1. **Sliding Time Windows**: In-memory rule detectors evaluate traffic over a sliding 10-second window (or 50-packet micro-batches). Low-and-slow reconnaissance scans distributed over hours or days are not currently correlated in-memory.
2. **Host Observation Frequency**: Host activity metrics reflect packet observation frequency where the host was seen as the source IP, rather than cumulative byte bandwidth.
3. **Elevated Privileges for Sniffing**: Live packet capture requires Administrator rights on Windows (and `CAP_NET_RAW` / `root` on Linux). Offline PCAP analysis operates fully unprivileged.
4. **Local Prototype Architecture**: Flask is configured with the standard WSGI development server bound exclusively to `127.0.0.1` for safe local evaluation.

---

## 13. Ethical Use & Defensive Authorization Disclaimer

> **IMPORTANT DEFENSIVE SECURITY NOTICE**:
> NetGuard is an educational, diagnostic, and defensive cybersecurity project designed for monitoring networks and devices that the operator **owns or has explicit, documented authorization to assess**.
>
> It does **not** include automated counter-attack execution, payload injection, or offensive network exploitation capabilities. Never deploy packet sniffers on networks where you lack explicit monitoring permissions.

---

## 14. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
