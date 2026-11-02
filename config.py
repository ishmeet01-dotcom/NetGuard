"""
NetGuard Configuration Module
Centralized settings for packet capture, detection thresholds, scoring, and storage.
"""

from pathlib import Path
from typing import Dict, Any

# Base Directories
BASE_DIR: Path = Path(__file__).resolve().parent
SAMPLES_DIR: Path = BASE_DIR / "samples"
LOGS_DIR: Path = BASE_DIR / "logs"
DB_PATH: Path = BASE_DIR / "netguard.db"

# Capture Settings
DEFAULT_INTERFACE: str = ""  # Auto-select or loopback if empty
BUFFER_SIZE: int = 65536
MAX_PCAP_STREAM_PACKETS: int = 500000
WINDOW_SIZE_SECONDS: float = 2.0  # Time-window for feature aggregation and detection

# Detection Engine Settings & Thresholds (Configurable)
DETECTION_THRESHOLDS: Dict[str, Any] = {
    # Port Scan: unique destination ports probed on single target within window
    "port_scan_min_ports": 15,
    "port_scan_window_sec": 10.0,

    # SYN Flood: high rate of TCP SYN-only packets within window
    "syn_flood_pps_threshold": 80.0,
    "syn_flood_min_packets": 50,
    "syn_flood_window_sec": 5.0,

    # UDP Flood: high-rate UDP traffic directed at target
    "udp_flood_pps_threshold": 100.0,
    "udp_flood_min_packets": 60,
    "udp_flood_window_sec": 5.0,

    # ICMP Flood: excessive ICMP request rate (Ping flood)
    "icmp_flood_pps_threshold": 40.0,
    "icmp_flood_min_packets": 30,
    "icmp_flood_window_sec": 5.0,

    # ARP Anomaly: unexpected MAC-IP mapping change within observation period
    "arp_observation_window_sec": 60.0,
    "arp_mapping_history_size": 512,

    # Statistical Anomaly: deviation from baseline traffic metrics
    "anomaly_z_score_threshold": 3.0,
    "anomaly_min_samples": 30,
    "anomaly_rate_threshold_pps": 500.0,
    "anomaly_source_concentration_ratio": 0.90,

    # Duplicate Alert Suppression Window
    "duplicate_suppression_window_sec": 5.0,
}

# Detector Activation Switches
ENABLED_DETECTORS: Dict[str, bool] = {
    "port_scan": True,
    "syn_flood": True,
    "udp_flood": True,
    "icmp_flood": True,
    "arp_anomaly": True,
    "statistical_anomaly": True,
}

# Risk Scoring Configuration
RISK_CONFIG: Dict[str, Any] = {
    "severity_levels": {
        "LOW": (0, 29),
        "MEDIUM": (30, 59),
        "HIGH": (60, 79),
        "CRITICAL": (80, 100),
    },
    "base_scores": {
        "PORT_SCAN": 60.0,
        "SYN_FLOOD": 90.0,
        "UDP_FLOOD": 85.0,
        "ICMP_FLOOD": 75.0,
        "ARP_ANOMALY": 85.0,
        "STATISTICAL_ANOMALY": 40.0,
    },
}

# Alert & Database Configuration
ALERT_CONFIG: Dict[str, Any] = {
    "valid_statuses": ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
    "deduplication_window_sec": 10.0,
}

DB_BATCH_SIZE: int = 1000

# Live Capture & Background Monitoring Settings
CAPTURE_QUEUE_MAXSIZE: int = 10000
PROCESSING_BATCH_SIZE: int = 50
MONITOR_WINDOW_SECONDS: float = 2.0
STATS_UPDATE_INTERVAL_SEC: float = 1.0
WORKER_SHUTDOWN_TIMEOUT_SEC: float = 3.0
DEFAULT_CAPTURE_FILTER: str = ""

# API Server & Upload Security Settings
SERVER_HOST: str = "127.0.0.1"
SERVER_PORT: int = 5000
DEBUG_MODE: bool = False
MAX_PCAP_UPLOAD_BYTES: int = 10 * 1024 * 1024  # 10 MB
ALLOWED_PCAP_EXTENSIONS: list = [".pcap", ".pcapng", ".cap"]

# Ensure required directories exist
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

