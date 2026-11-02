"""
NetGuard Port Scan Detector
Identifies reconnaissance activities where a source host probes multiple unique destination
ports on a target within a configurable time window.
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict

from config import DETECTION_THRESHOLDS
from preprocessing.packet_parser import PacketRecord


class PortScanDetector:
    """
    Detects port scanning behavior by analyzing unique destination port access patterns
    grouped by (source IP, destination IP) over a time window.
    """

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        cfg = thresholds or DETECTION_THRESHOLDS
        self.min_unique_ports: int = int(cfg.get("port_scan_min_ports", 15))
        self.window_sec: float = float(cfg.get("port_scan_window_sec", 10.0))

    def detect(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Analyze packet sequence for port scanning activities.
        Returns a list of standardized detection result dictionaries.
        """
        if not packets:
            return []

        # Filter packets that have valid IPs and destination ports
        ip_packets = [
            p for p in packets
            if p.src_ip and p.dst_ip and p.dst_port is not None and (0 <= p.dst_port <= 65535)
        ]
        if not ip_packets:
            return []

        # Sort chronologically by timestamp
        sorted_packets = sorted(ip_packets, key=lambda p: p.timestamp)

        # Group by (src_ip, dst_ip)
        pairs: Dict[tuple, List[PacketRecord]] = defaultdict(list)
        for pkt in sorted_packets:
            pairs[(pkt.src_ip, pkt.dst_ip)].append(pkt)

        detections: List[Dict[str, Any]] = []

        for (src_ip, dst_ip), pair_pkts in pairs.items():
            # Sliding time window analysis
            start_idx = 0
            n = len(pair_pkts)

            # Track detected window ranges to prevent duplicate triggers for same scan segment
            last_reported_end_ts = -1.0

            for end_idx in range(n):
                current_pkt = pair_pkts[end_idx]
                current_ts = current_pkt.timestamp

                # Advance start_idx to maintain sliding window
                while start_idx < end_idx and (current_ts - pair_pkts[start_idx].timestamp) > self.window_sec:
                    start_idx += 1

                window_slice = pair_pkts[start_idx : end_idx + 1]
                unique_ports = {p.dst_port for p in window_slice if p.dst_port is not None}

                if len(unique_ports) >= self.min_unique_ports:
                    # Check if already covered by recent detection in this pair
                    if current_ts <= last_reported_end_ts:
                        continue

                    # Analyze TCP SYN scan characteristics
                    tcp_pkts = [p for p in window_slice if p.protocol == "TCP"]
                    syn_only_pkts = [p for p in tcp_pkts if p.is_syn]
                    is_syn_scan = len(syn_only_pkts) >= (len(tcp_pkts) * 0.7) if tcp_pkts else False

                    window_duration = max(0.001, current_ts - pair_pkts[start_idx].timestamp)
                    sample_ports = sorted(list(unique_ports))[:10]

                    # Confidence determination
                    if is_syn_scan and len(unique_ports) >= (self.min_unique_ports * 2):
                        confidence = "HIGH"
                    elif len(unique_ports) >= self.min_unique_ports:
                        confidence = "MEDIUM"
                    else:
                        confidence = "LOW"

                    scan_type_desc = "TCP SYN Port Scan" if is_syn_scan else "Multi-Port Probe Scan"
                    desc = (
                        f"{scan_type_desc} detected: {src_ip} probed {len(unique_ports)} unique ports "
                        f"on target {dst_ip} within {window_duration:.2f}s "
                        f"(Threshold: {self.min_unique_ports} ports in {self.window_sec}s)."
                    )

                    detections.append({
                        "detected": True,
                        "threat_type": "PORT_SCAN",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "timestamp": round(current_ts, 4),
                        "description": desc,
                        "evidence": {
                            "unique_ports_count": len(unique_ports),
                            "threshold_ports": self.min_unique_ports,
                            "window_duration_seconds": round(window_duration, 3),
                            "is_syn_scan": is_syn_scan,
                            "sample_ports": sample_ports,
                            "total_probe_packets": len(window_slice),
                        },
                        "confidence": confidence,
                    })

                    last_reported_end_ts = current_ts

        return detections
