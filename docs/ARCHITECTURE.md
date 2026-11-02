# NetGuard — System Architecture Documentation

This document describes the architectural design, data pipelines, thread lifecycle, and storage models of **NetGuard**, an enterprise-grade Network Intrusion Detection System (NIDS).

---

## 1. End-to-End System Architecture

```mermaid
flowchart TD
    subgraph Ingestion["Ingestion Layer"]
        A1[Live Network Traffic\nScapy Sniffer Engine] -->|Real-time Frames| B[Bounded Packet Queue\nmaxsize=10,000]
        A2[Offline PCAP / PCAPNG\nStreaming Reader] -->|Chunked Packets| C[Packet Parser\nStandardized PacketRecord]
        B -->|Producer-Consumer| C
    end

    subgraph Preprocessing["Preprocessing & Feature Extraction"]
        C --> D[Traffic Cleaner\nValidation & Sanitization]
        D --> E[NumPy Traffic Analyzer\nVectorized Array Analytics]
        E --> F[Feature Extractor\nStatistical Aggregates & L4 Flags]
    end

    subgraph Detection["Threat Detection & Scoring Engine"]
        F --> G[Detection Rule Engine\nCoordinated Execution]
        G --> H1[Port Scan Detector\nTCP SYN vs Connect]
        G --> H2[Flood Detector\nSYN, UDP, ICMP Rates]
        G --> H3[ARP Anomaly Detector\nIP-MAC Cache Tracker]
        G --> H4[Statistical Anomaly Detector\nZ-Score & Source Concentration]
        H1 & H2 & H3 & H4 --> I[Heuristic Risk Scorer\nBase Score + Modifiers, 0-100]
        I --> J[Alert Manager\nDeduplication & State Machine]
    end

    subgraph Persistence["Storage & API Layer"]
        D --> K[(SQLite Database\nnetguard.db)]
        F --> K
        J --> K
        K --> L[Flask REST API Service\n127.0.0.1:5000]
    end

    subgraph Presentation["Security Operations Center (SOC) Dashboard"]
        L <-->|REST Polling / JSON| M[Single-Page Application\nHTML5 / CSS3 / Vanilla JS]
        M --> N1[Overview & KPI Metrics]
        M --> N2[Chart.js Visualizations]
        M --> N3[Live Sniffer Controls]
        M --> N4[Network Traffic Explorer]
        M --> N5[Threat Intelligence Matrix]
        M --> N6[Alert Dossier & Lifecycle Drawer]
        M --> N7[Known Hosts Inventory]
        M --> N8[Offline PCAP Analyzer]
        M --> N9[System Health & Telemetry]
    end
```

---

## 2. Ingestion & Threading Lifecycle

NetGuard separates live packet capture from analytic processing using a **multi-threaded producer-consumer pattern**:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Security Operator
    participant API as Flask REST API
    participant Mgr as MonitorManager
    participant Cap as LiveCaptureEngine (Scapy)
    participant Q as Bounded Queue (10,000)
    participant Worker as Worker Thread
    participant DB as SQLite (netguard.db)

    Operator->>API: POST /api/monitor/start {interface, filter}
    API->>Mgr: start_monitoring()
    Note over Mgr: Acquire threading lock<br/>Verify no existing session<br/>Clear queue buffer
    Mgr->>Worker: Start NetGuard-MonitorWorker (daemon=True)
    Mgr->>Cap: start_capture(enqueue_callback)
    Cap-->>Mgr: Sniffer thread active

    loop Live Capture Loop
        Cap->>Q: put_nowait(packet)
        alt Queue Full (>10,000)
            Q-->>Cap: queue.Full
            Cap->>Mgr: Increment dropped_packets counter
        end
    end

    loop Consumer Worker Loop
        Worker->>Q: get(timeout=0.2s)
        Worker->>Worker: Buffer into micro-batch (50 pkts or 2.0s window)
        Worker->>Worker: Run NumPy feature extraction & Rule Engine
        Worker->>DB: Batch insert traffic & persist alerts
    end

    Operator->>API: POST /api/monitor/stop
    API->>Mgr: stop_monitoring()
    Mgr->>Cap: stop_capture()
    Mgr->>Worker: Set _stop_event
    Note over Worker: Drain remaining queue<br/>Flush final window buffer to DB
    Worker-->>Mgr: Thread terminated (join)
    Mgr-->>API: Monitoring terminated cleanly
    API-->>Operator: HTTP 200 OK
```

### Key Concurrency Protections:
1. **Re-entrancy Guard**: Starting a capture session while one is already active raises `RuntimeError` and returns `HTTP 409 Conflict`.
2. **Backpressure Handling**: If the queue fills past 10,000 items, packets are dropped and accounted for in `dropped_packets` rather than consuming unbounded system memory.
3. **Graceful Drain**: When stopping, the worker thread continues draining all remaining queue elements and flushes its buffer to SQLite before exiting.
4. **Isolated Exceptions**: Database write failures or malformed packet anomalies caught inside the worker loop are logged to `last_error` and do not crash the sniffer thread.

---

## 3. Data Pipeline & Detection Architecture

### A. Preprocessing & Normalization
1. **`PacketRecord`**: Normalized dataclass containing:
   - `timestamp` (float)
   - `src_ip`, `dst_ip` (IPv4 or IPv6 string)
   - `src_mac`, `dst_mac` (Normalized lower-case MAC)
   - `src_port`, `dst_port` (Integer or None)
   - `protocol` (`TCP`, `UDP`, `ICMP`, `ARP`, or `OTHER`)
   - `packet_size` (Integer byte length)
   - `tcp_flags` (String representation, e.g. `SYN`, `SYN-ACK`, `ACK`, `FIN`, `RST`)
2. **`TrafficCleaner`**: Verifies valid timestamps, normalizes IP addresses, strips invalid headers, and flags anomalies.

### B. Feature Extraction (NumPy)
The `NumPyTrafficAnalyzer` module performs zero-copy vectorized calculations over packet batches:
- Vectorized sizes: mean, standard deviation, min, max, percentiles (p25, p50, p95).
- Transfer rates: packets per second (PPS) and bytes per second (BPS).
- Unique entities: unique source IPs, destination IPs, and destination ports using `np.unique()`.
- Protocol breakdown and TCP flag distributions.

### C. Coordinated Threat Detectors
1. **`PortScanDetector`**: Tracks sliding windows of destination ports per source IP against a target. Differentiates single-port multi-packet bursts from genuine reconnaissance probing $\ge 15$ ports in 10.0s.
2. **`FloodDetector`**: Measures instantaneous volumetric rates:
   - **SYN Flood**: Evaluates TCP SYN-only packets exceeding 80.0 PPS with minimum 50 packets.
   - **UDP Flood**: Evaluates UDP volume exceeding 100.0 PPS with minimum 60 packets.
   - **ICMP Flood**: Evaluates echo requests exceeding 40.0 PPS with minimum 30 packets.
3. **`ARPAnomalyDetector`**: Maintains an IP-to-MAC association state cache. Identifies conflicting MAC mappings for existing IP records within observation windows.
4. **`StatisticalAnomalyDetector`**: Evaluates burst spikes against baseline rates ($\ge 500$ PPS), packet size Z-scores ($Z \ge 3.0$), and high source concentration ratios ($\ge 90\%$).

### D. Heuristic Risk Scoring
Base threat weights are adjusted based on empirical evidence:

$$\text{Final Score} = \text{np.clip}\left(\text{Base Score} + \sum \text{Modifiers},\; 0,\; 100\right)$$

- Base Scores:
  - `PORT_SCAN`: 60.0
  - `SYN_FLOOD`: 90.0
  - `UDP_FLOOD`: 85.0
  - `ICMP_FLOOD`: 75.0
  - `ARP_ANOMALY`: 85.0
  - `STATISTICAL_ANOMALY`: 40.0
- Severity Boundaries:
  - **CRITICAL**: 80 – 100
  - **HIGH**: 60 – 79
  - **MEDIUM**: 30 – 59
  - **LOW**: 0 – 29

---

## 4. Database Schema (SQLite)

NetGuard persists network telemetry in `netguard.db` using 4 indexed relational tables:

```mermaid
erDiagram
    TRAFFIC_RECORDS {
        INTEGER id PK
        REAL timestamp
        TEXT source_ip
        TEXT destination_ip
        INTEGER source_port
        INTEGER destination_port
        TEXT protocol
        INTEGER packet_size
        TEXT tcp_flags
    }

    SECURITY_ALERTS {
        TEXT alert_id PK
        REAL timestamp
        TEXT source_ip
        TEXT destination_ip
        TEXT threat_type
        TEXT severity
        REAL risk_score
        TEXT status
        TEXT description
        TEXT evidence_json
    }

    NETWORK_STATISTICS {
        INTEGER id PK
        REAL timestamp
        INTEGER total_packets
        INTEGER total_bytes
        REAL packets_per_second
        REAL bytes_per_second
        TEXT protocol_distribution_json
    }

    KNOWN_HOSTS {
        INTEGER id PK
        TEXT ip_address UK
        TEXT mac_address
        REAL first_seen
        REAL last_seen
        INTEGER observation_count
    }

    KNOWN_HOSTS ||--o{ TRAFFIC_RECORDS : "generates"
    SECURITY_ALERTS ||--o{ TRAFFIC_RECORDS : "references"
```

---

## 5. Security & Isolation Controls

1. **Localhost Binding**: Flask binds strictly to `127.0.0.1:5000` by default; it is never exposed to public interfaces (`0.0.0.0`).
2. **PCAP Upload Sandboxing**:
   - Magic byte header inspection validates genuine PCAP/PCAPNG signatures before reading.
   - Files are stored in secure OS temp files (`tempfile.mkstemp`) and deleted in a `finally` block on both success and failure.
   - Client filenames are sanitized with `os.path.basename` to prevent directory traversal.
   - Maximum upload size is strictly capped at 10 MB (HTTP 413).
3. **SQL Injection Resistance**: All SQL queries utilize parameterized statements (`?` placeholders) through connection context managers.
4. **XSS Protection**: Frontend rendering escapes all dynamic strings (`Utils.escapeHTML()`) or uses `.textContent` for JSON payloads.
