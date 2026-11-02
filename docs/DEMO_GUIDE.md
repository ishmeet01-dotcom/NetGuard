# NetGuard — Demonstration & Evaluation Guide

This guide provides an end-to-end walkthrough for demonstrating NetGuard's offline traffic analysis, heuristic threat detection, SQLite persistence, and interactive SOC Dashboard.

---

## 1. Quick Demonstration Sequence (10 Steps)

### Step 1: Inspect Project Structure & Modules
Display the clean modular layout:
```powershell
Get-ChildItem -Directory
```
*Key talking points*: Modular division between packet ingestion (`capture/`), normalization (`preprocessing/`), vectorized analytics (`features/`), threat engines (`detection/`), scoring (`scoring/`), persistence (`database/`), and the web interface (`dashboard/`).

---

### Step 2: Analyze Baseline Benign Traffic
Run the offline parser against a clean sample capture:
```powershell
python main.py --sample
```
*Expected Output*:
- Ingestion of 10 packets across TCP, UDP, ICMP, and ARP.
- NumPy vectorized packet size percentiles (p25, p50, p95), mean, and standard deviation.
- Detection engine confirmation: `[i] No suspicious activity detected under current thresholds.`
- Database batch insertion confirmation.

---

### Step 3: Analyze Suspicious Network Capture
Analyze traffic containing simulated port scan and ARP anomaly events:
```powershell
python main.py --pcap samples/suspicious_sample.pcap
```
*Expected Output*:
- High SYN-to-TCP packet ratio ($100\%$).
- 2 security alerts generated and categorized:
  1. `PORT_SCAN` [HIGH] (Score: 65/100) — Multi-port probing targeting port range 1000–1019.
  2. `ARP_ANOMALY` [CRITICAL] (Score: 90/100) — Conflicting MAC claim for IP `192.168.1.1`.

---

### Step 4: Review Alert Evidence & Heuristic Risk Scores
Query the stored alerts from SQLite:
```powershell
python main.py --alerts
```
*Key talking points*:
- Heuristic scoring methodology combines base threat severity with empirical evidence adjustments clamped between 0 and 100 (`np.clip`).
- Confidence is documented as an **evidence classification** based on observable protocol flags, not an arbitrary black-box probability.

---

### Step 5: Inspect Known Host Inventory & Database Aggregates
View discovered network endpoints and database table volume:
```powershell
python main.py --hosts
python main.py --stats
```

---

### Step 6: Launch the Enterprise SOC Dashboard
Start the local Flask application:
```powershell
python main.py --server
```
Navigate in your web browser to:
```text
http://127.0.0.1:5000
```

---

### Step 7: Explore Overview Dashboard & Visualizations
In the web interface:
1. **KPI Metric Cards**: Observe Total Packets, Total Network Bytes, PPS, Active Hosts, and Critical Alerts sourced directly from SQLite.
2. **Chart.js Graphs**:
   - *Network Traffic Timeline*: Review packets-per-second and bytes-per-second over time.
   - *Protocol Distribution*: Review L4 protocol breakdown.
   - *Alert Severity Profile*: Examine distribution of Critical, High, Medium, and Low incidents.
   - *Most Observed Hosts*: Inspect endpoints by packet occurrence frequency.

---

### Step 8: Navigate Security Operations Views
Click through the sidebar items:
- **Network Traffic**: Test protocol dropdown filtering, source/destination IP filters, and the "Copy IP" action.
- **Threat Intelligence**: Review the 6 threat category matrix cards and suspicious source distributions.
- **Alert Management**: Click an alert row to slide open the **Alert Investigation Dossier**, review the raw evidence JSON, and update the investigation status (`NEW` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `RESOLVED`).
- **Host Monitoring**: Search endpoints by IP or MAC address.
- **System Health**: Verify Flask REST API, SQLite database, worker thread status, and bounded queue capacity.

---

### Step 9: Demonstrate Interactive PCAP Drag-and-Drop
1. Navigate to the **PCAP Analyzer** view.
2. Drag and drop `samples/suspicious_sample.pcap` (or click "Browse Local Files").
3. Click **Execute Analysis**.
4. Observe the upload progress indicator, followed by the generated analysis dossier, protocol breakdown, and persisted security alerts.

---

### Step 10: Demonstrate Opt-In Live Sniffing (If Privileged)
1. Navigate to **Live Monitoring**.
2. Select your active network adapter from the dropdown list.
3. (Optional) Provide a BPF filter (e.g. `tcp`).
4. Click **Start Monitoring** to begin live packet ingestion. Observe the live status pulse and updating counters.
5. Click **Stop Monitoring**, review the confirmation prompt, and confirm termination. Note that final statistics are preserved.

---

## 2. Recommended Portfolio Screenshots

For a GitHub repository or portfolio presentation, capture the following views:

| Screenshot Recommendation | View / Element | Focus Area |
| :--- | :--- | :--- |
| **1. Overview Dashboard** | `http://127.0.0.1:5000` (`Overview`) | Highlights dark enterprise styling, KPI cards, and all 4 Chart.js visualizations. |
| **2. Alert Investigation Drawer** | `Alert Management` section | Open slideout dossier displaying raw evidence JSON and status management. |
| **3. Live Sniffer Telemetry** | `Live Monitoring` section | Active sniffer banner, BPF filter input, and real-time packet throughput grid. |
| **4. Offline PCAP Analyzer** | `PCAP Analyzer` section | Completed analysis report showing traffic volume and detected threats. |
| **5. CLI Analysis Pipeline** | Terminal window | Execution of `python main.py --pcap samples/suspicious_sample.pcap` showing ASCII banner, NumPy analytics, and detections. |

> **Note**: Always capture screenshots using synthetic or authorized demo PCAP captures. Never capture or commit production credentials, personal IP addresses, or proprietary network payloads.
