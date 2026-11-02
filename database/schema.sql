-- NetGuard SQLite Database Schema
-- Defines tables for traffic metadata, security alerts, network metrics, and known hosts.

-- 1. Traffic Records Table
CREATE TABLE IF NOT EXISTS traffic_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL,
    packet_size INTEGER NOT NULL,
    tcp_flags TEXT
);

CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_records(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic_records(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip ON traffic_records(destination_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON traffic_records(protocol);

-- 2. Security Alerts Table
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    description TEXT NOT NULL,
    evidence_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON security_alerts(threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON security_alerts(source_ip);

-- 3. Network Statistics Table
CREATE TABLE IF NOT EXISTS network_statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    total_packets INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    packets_per_second REAL NOT NULL,
    bytes_per_second REAL NOT NULL,
    protocol_distribution_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON network_statistics(timestamp);

-- 4. Known Hosts Table
CREATE TABLE IF NOT EXISTS known_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON known_hosts(ip_address);
