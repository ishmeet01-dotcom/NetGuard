# NetGuard — REST API Reference Documentation

NetGuard exposes a RESTful API over HTTP to support real-time network monitoring, alert management, traffic inspection, and capture analysis.

- **Base URL**: `http://127.0.0.1:5000/api`
- **Default Binding**: `127.0.0.1` (Localhost loopback only)
- **Response Format**: `application/json`

---

## 1. System Status & Diagnostics

### `GET /api/status`
Returns high-level system readiness, monitoring engine state, and database aggregation counts.

- **Query Parameters**: None
- **Response**: `200 OK`
```json
{
  "success": true,
  "status": "online",
  "monitoring": {
    "is_monitoring": false,
    "interface": null,
    "uptime_seconds": 0.0,
    "total_packets": 96,
    "total_bytes": 6844,
    "current_pps": 0.0,
    "current_bps": 0.0,
    "queue_size": 0,
    "dropped_packets": 0
  },
  "counts": {
    "total_traffic_packets": 96,
    "total_alerts": 2,
    "critical_threats": 1,
    "active_hosts": 5
  }
}
```

---

## 2. Network Interface Enumeration

### `GET /api/interfaces`
Lists all physical, virtual, and loopback network adapters discovered on the host.

- **Query Parameters**: None
- **Response**: `200 OK`
```json
{
  "success": true,
  "count": 3,
  "interfaces": [
    {
      "id": "\\Device\\NPF_{GUID}",
      "name": "Wi-Fi",
      "description": "Intel(R) Wi-Fi 6 AX201",
      "ip": "192.168.1.15",
      "mac": "38:8d:3d:1d:35:66",
      "is_default": true
    }
  ]
}
```

---

## 3. Live Monitoring Controls

### `POST /api/monitor/start`
Starts a live background packet sniffing session on the specified adapter.

- **Request Body** (`application/json`):
```json
{
  "interface": "Wi-Fi",
  "filter": "tcp port 80"
}
```
- **Response**: `200 OK`
```json
{
  "success": true,
  "message": "Monitoring initiated successfully.",
  "interface": "Wi-Fi",
  "filter": "tcp port 80"
}
```
- **Error Responses**:
  - `400 Bad Request`: Invalid or unrecognized interface name.
  - `409 Conflict`: Monitoring session is already active.
  - `500 Internal Server Error`: Unhandled sniffer startup exception or permission error.

---

### `POST /api/monitor/stop`
Terminates active packet capture, drains the queued packet buffer, flushes records to SQLite, and preserves final statistics.

- **Request Body**: None
- **Response**: `200 OK`
```json
{
  "success": true,
  "message": "Monitoring stopped successfully."
}
```

---

### `GET /api/monitor/status`
Returns real-time operational telemetry and throughput statistics for the active or most recent capture session.

- **Query Parameters**: None
- **Response**: `200 OK`
```json
{
  "success": true,
  "data": {
    "is_monitoring": true,
    "interface": "Wi-Fi",
    "bpf_filter": "",
    "uptime_seconds": 45.2,
    "total_packets": 1420,
    "total_bytes": 948200,
    "current_pps": 32.5,
    "current_bps": 21450.0,
    "protocol_counts": {
      "TCP": 1100,
      "UDP": 280,
      "ICMP": 20,
      "ARP": 20
    },
    "active_sources_count": 8,
    "active_destinations_count": 14,
    "detected_threats": 2,
    "generated_alerts": 2,
    "dropped_packets": 0,
    "queue_size": 12,
    "queue_capacity": 10000,
    "last_error": null
  }
}
```

---

## 4. Network Statistics

### `GET /api/statistics`
Provides aggregated network volume and protocol counts.

- **Response**: `200 OK`
```json
{
  "success": true,
  "total_packets": 1420,
  "total_bytes": 948200,
  "packets_per_second": 32.5,
  "bytes_per_second": 21450.0,
  "protocol_counts": {
    "TCP": 1100,
    "UDP": 280,
    "ICMP": 20,
    "ARP": 20
  },
  "active_sources": 8,
  "active_destinations": 14
}
```

---

### `GET /api/statistics/history`
Returns chronological snapshots of throughput metrics persisted in SQLite.

- **Query Parameters**:
  - `limit` (optional integer, default: `50`, max: `200`)
- **Response**: `200 OK`
```json
{
  "success": true,
  "count": 1,
  "history": [
    {
      "id": 1,
      "timestamp": 1793596775.32,
      "total_packets": 1420,
      "total_bytes": 948200,
      "packets_per_second": 32.5,
      "bytes_per_second": 21450.0,
      "protocols": { "TCP": 1100, "UDP": 280 }
    }
  ]
}
```

---

## 5. Network Traffic Records

### `GET /api/traffic`
Retrieves paginated packet records from the database with parameterized multi-criteria filtering.

- **Query Parameters**:
  - `limit` (optional integer, default: `50`, max: `500`)
  - `offset` (optional integer, default: `0`)
  - `protocol` (optional string, e.g. `TCP`, `UDP`, `ICMP`, `ARP`)
  - `source_ip` (optional string, exact match)
  - `destination_ip` (optional string, exact match)
- **Response**: `200 OK`
```json
{
  "success": true,
  "count": 1,
  "limit": 50,
  "offset": 0,
  "records": [
    {
      "id": 101,
      "timestamp": 1793596775.32,
      "source_ip": "192.168.1.250",
      "destination_ip": "192.168.1.1",
      "source_port": 45120,
      "destination_port": 80,
      "protocol": "TCP",
      "packet_size": 54,
      "tcp_flags": "SYN"
    }
  ]
}
```
- **Error Response**:
  - `400 Bad Request`: Non-numeric or negative `limit` or `offset`.

---

## 6. Security Alerts

### `GET /api/alerts`
Lists security alerts with filtering and pagination.

- **Query Parameters**:
  - `limit` (optional integer, default: `50`, max: `500`)
  - `offset` (optional integer, default: `0`)
  - `severity` (optional string: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - `threat_type` (optional string: `PORT_SCAN`, `SYN_FLOOD`, `UDP_FLOOD`, `ICMP_FLOOD`, `ARP_ANOMALY`, `STATISTICAL_ANOMALY`)
  - `status` (optional string: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`)
  - `source_ip` (optional string)
  - `destination_ip` (optional string)
- **Response**: `200 OK`
```json
{
  "success": true,
  "count": 1,
  "alerts": [
    {
      "alert_id": "ALT-B419E37CC3",
      "timestamp": 1793596775.32,
      "threat_type": "PORT_SCAN",
      "source_ip": "192.168.1.250",
      "destination_ip": "192.168.1.1",
      "severity": "HIGH",
      "risk_score": 65.0,
      "status": "NEW",
      "description": "TCP SYN Port Scan detected: 192.168.1.250 probed 15 unique ports on target 192.168.1.1 within 0.00s.",
      "evidence": { "unique_ports": 15, "probed_ports": [1000, 1001] }
    }
  ]
}
```

---

### `GET /api/alerts/<alert_id>`
Retrieves complete details and evidence payload for a specific alert.

- **Path Parameters**:
  - `alert_id` (string, e.g. `ALT-B419E37CC3`)
- **Response**: `200 OK`
- **Error Response**:
  - `404 Not Found`: Alert ID does not exist in the database.

---

### `PATCH /api/alerts/<alert_id>/status`
Updates the investigation status of an existing security alert.

- **Path Parameters**:
  - `alert_id` (string)
- **Request Body** (`application/json`):
```json
{
  "status": "INVESTIGATING"
}
```
- **Allowed Status Values**:
  - `NEW`
  - `INVESTIGATING`
  - `RESOLVED`
  - `FALSE_POSITIVE`
- **Response**: `200 OK`
```json
{
  "success": true,
  "message": "Alert 'ALT-B419E37CC3' status updated to 'INVESTIGATING'.",
  "alert_id": "ALT-B419E37CC3",
  "status": "INVESTIGATING"
}
```
- **Error Responses**:
  - `400 Bad Request`: Invalid status string provided.
  - `404 Not Found`: Alert ID does not exist.

---

## 7. Known Active Hosts

### `GET /api/hosts`
Returns discovered network hosts tracked in SQLite.

- **Query Parameters**:
  - `limit` (optional integer, default: `100`, max: `500`)
  - `search` (optional string: filter by partial IP or MAC address)
- **Response**: `200 OK`
```json
{
  "success": true,
  "count": 2,
  "hosts": [
    {
      "id": 1,
      "ip_address": "192.168.1.250",
      "mac_address": "00:0c:29:11:22:33",
      "first_seen": 1793596000.0,
      "last_seen": 1793596775.32,
      "observation_count": 60
    }
  ]
}
```

---

## 8. Offline PCAP Upload & Analysis

### `POST /api/analyze/pcap`
Accepts a capture file upload (`.pcap`, `.pcapng`, `.cap`), runs the full preprocessing, detection, scoring, and persistence pipeline in a secure temporary sandbox, and returns the analysis dossier.

- **Request Format**: `multipart/form-data`
- **Field Name**: `file`
- **Size Limit**: 10 MB (`MAX_PCAP_UPLOAD_BYTES`)
- **Response**: `200 OK`
```json
{
  "success": true,
  "filename": "suspicious_sample.pcap",
  "total_packets": 22,
  "traffic_duration_seconds": 0.003,
  "protocols": {
    "TCP": 20,
    "ARP": 2
  },
  "summary": {
    "total_bytes": 1164,
    "packets_per_second": 7399.73,
    "bytes_per_second": 391513.22,
    "avg_packet_size": 52.91
  },
  "detected_threats_count": 2,
  "alerts": [
    {
      "alert_id": "ALT-B419E37CC3",
      "threat_type": "PORT_SCAN",
      "severity": "HIGH",
      "risk_score": 65.0
    }
  ],
  "database_records_inserted": 22
}
```
- **Error Responses**:
  - `400 Bad Request`: No file uploaded, empty file, invalid file extension, or file signature (magic bytes) mismatch.
  - `413 Request Entity Too Large`: File exceeds the 10 MB upload ceiling.
  - `500 Internal Server Error`: Unhandled PCAP parsing or extraction failure.
