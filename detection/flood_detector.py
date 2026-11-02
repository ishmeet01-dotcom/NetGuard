"""
NetGuard Flood Detector Module
Detects volumetric and protocol flood attacks: TCP SYN floods, UDP floods, and ICMP floods.
"""

from typing import List, Dict, Any, Optional
from collections import defaultdict

from config import DETECTION_THRESHOLDS
from preprocessing.packet_parser import PacketRecord


class FloodDetector:
    """
    Volumetric flood detector for TCP SYN, UDP, and ICMP traffic streams.
    Requires both minimum packet counts and rate thresholds across a time window.
    """

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        cfg = thresholds or DETECTION_THRESHOLDS

        # SYN Flood configuration
        self.syn_pps_threshold: float = float(cfg.get("syn_flood_pps_threshold", 80.0))
        self.syn_min_packets: int = int(cfg.get("syn_flood_min_packets", 50))
        self.syn_window_sec: float = float(cfg.get("syn_flood_window_sec", 5.0))

        # UDP Flood configuration
        self.udp_pps_threshold: float = float(cfg.get("udp_flood_pps_threshold", 100.0))
        self.udp_min_packets: int = int(cfg.get("udp_flood_min_packets", 60))
        self.udp_window_sec: float = float(cfg.get("udp_flood_window_sec", 5.0))

        # ICMP Flood configuration
        self.icmp_pps_threshold: float = float(cfg.get("icmp_flood_pps_threshold", 40.0))
        self.icmp_min_packets: int = int(cfg.get("icmp_flood_min_packets", 30))
        self.icmp_window_sec: float = float(cfg.get("icmp_flood_window_sec", 5.0))

    def detect(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """Run all flood detection routines and aggregate findings."""
        if not packets:
            return []

        results: List[Dict[str, Any]] = []
        results.extend(self.detect_syn_flood(packets))
        results.extend(self.detect_udp_flood(packets))
        results.extend(self.detect_icmp_flood(packets))
        return results

    def detect_syn_flood(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Detect abnormally high rates of TCP SYN-only packets directed at a target.
        SYN+ACK and other completed handshake packets are explicitly excluded.
        """
        # Filter TCP SYN-only packets directed at a valid destination
        syn_pkts = [p for p in packets if p.protocol == "TCP" and p.is_syn and p.dst_ip]
        if len(syn_pkts) < self.syn_min_packets:
            return []

        # Sort chronologically
        syn_pkts = sorted(syn_pkts, key=lambda p: p.timestamp)

        # Group by target IP
        target_groups: Dict[str, List[PacketRecord]] = defaultdict(list)
        for p in syn_pkts:
            target_groups[p.dst_ip].append(p)

        detections: List[Dict[str, Any]] = []

        for target_ip, pkts in target_groups.items():
            if len(pkts) < self.syn_min_packets:
                continue

            start_idx = 0
            n = len(pkts)
            last_reported_end_ts = -1.0

            for end_idx in range(n):
                current_ts = pkts[end_idx].timestamp
                while start_idx < end_idx and (current_ts - pkts[start_idx].timestamp) > self.syn_window_sec:
                    start_idx += 1

                window_slice = pkts[start_idx : end_idx + 1]
                window_count = len(window_slice)

                if window_count >= self.syn_min_packets:
                    duration = max(0.01, current_ts - pkts[start_idx].timestamp)
                    pps = window_count / duration

                    if pps >= self.syn_pps_threshold:
                        if current_ts <= last_reported_end_ts:
                            continue

                        # Analyze source IP diversity
                        sources = [p.src_ip for p in window_slice if p.src_ip]
                        src_counts: Dict[str, int] = defaultdict(int)
                        for s in sources:
                            src_counts[s] += 1

                        primary_src = max(src_counts.items(), key=lambda x: x[1])[0] if src_counts else "UNKNOWN"
                        unique_sources = len(src_counts)

                        confidence = "HIGH" if (pps >= self.syn_pps_threshold * 1.5 and window_count >= self.syn_min_packets * 1.5) else "MEDIUM"
                        src_desc = f"{primary_src}" if unique_sources == 1 else f"{primary_src} (+ {unique_sources - 1} distributed sources)"

                        desc = (
                            f"TCP SYN Flood detected: Target {target_ip} received {window_count} SYN packets "
                            f"at {pps:.1f} packets/sec from {src_desc} over {duration:.2f}s "
                            f"(Thresholds: >= {self.syn_min_packets} pkts, >= {self.syn_pps_threshold} pps)."
                        )

                        detections.append({
                            "detected": True,
                            "threat_type": "SYN_FLOOD",
                            "source_ip": primary_src,
                            "destination_ip": target_ip,
                            "timestamp": round(current_ts, 4),
                            "description": desc,
                            "evidence": {
                                "syn_packets": window_count,
                                "duration_seconds": round(duration, 3),
                                "packets_per_second": round(pps, 1),
                                "threshold_pps": self.syn_pps_threshold,
                                "threshold_min_packets": self.syn_min_packets,
                                "unique_sources_count": unique_sources,
                            },
                            "confidence": confidence,
                        })
                        last_reported_end_ts = current_ts

        return detections

    def detect_udp_flood(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Detect abnormally high-rate UDP streams directed toward a victim host.
        """
        udp_pkts = [p for p in packets if p.protocol == "UDP" and p.dst_ip]
        if len(udp_pkts) < self.udp_min_packets:
            return []

        udp_pkts = sorted(udp_pkts, key=lambda p: p.timestamp)

        target_groups: Dict[str, List[PacketRecord]] = defaultdict(list)
        for p in udp_pkts:
            target_groups[p.dst_ip].append(p)

        detections: List[Dict[str, Any]] = []

        for target_ip, pkts in target_groups.items():
            if len(pkts) < self.udp_min_packets:
                continue

            start_idx = 0
            n = len(pkts)
            last_reported_end_ts = -1.0

            for end_idx in range(n):
                current_ts = pkts[end_idx].timestamp
                while start_idx < end_idx and (current_ts - pkts[start_idx].timestamp) > self.udp_window_sec:
                    start_idx += 1

                window_slice = pkts[start_idx : end_idx + 1]
                window_count = len(window_slice)

                if window_count >= self.udp_min_packets:
                    duration = max(0.01, current_ts - pkts[start_idx].timestamp)
                    pps = window_count / duration

                    if pps >= self.udp_pps_threshold:
                        if current_ts <= last_reported_end_ts:
                            continue

                        sources = [p.src_ip for p in window_slice if p.src_ip]
                        src_counts: Dict[str, int] = defaultdict(int)
                        for s in sources:
                            src_counts[s] += 1

                        primary_src = max(src_counts.items(), key=lambda x: x[1])[0] if src_counts else "UNKNOWN"
                        unique_sources = len(src_counts)

                        ports = {p.dst_port for p in window_slice if p.dst_port is not None}
                        confidence = "HIGH" if (pps >= self.udp_pps_threshold * 1.5 and window_count >= self.udp_min_packets * 1.5) else "MEDIUM"

                        desc = (
                            f"UDP Flood detected: Target {target_ip} received {window_count} UDP packets "
                            f"at {pps:.1f} packets/sec across {len(ports)} target port(s) over {duration:.2f}s "
                            f"(Thresholds: >= {self.udp_min_packets} pkts, >= {self.udp_pps_threshold} pps)."
                        )

                        detections.append({
                            "detected": True,
                            "threat_type": "UDP_FLOOD",
                            "source_ip": primary_src,
                            "destination_ip": target_ip,
                            "timestamp": round(current_ts, 4),
                            "description": desc,
                            "evidence": {
                                "udp_packets": window_count,
                                "duration_seconds": round(duration, 3),
                                "packets_per_second": round(pps, 1),
                                "threshold_pps": self.udp_pps_threshold,
                                "threshold_min_packets": self.udp_min_packets,
                                "targeted_ports_count": len(ports),
                                "sample_ports": sorted(list(ports))[:5],
                                "unique_sources_count": unique_sources,
                            },
                            "confidence": confidence,
                        })
                        last_reported_end_ts = current_ts

        return detections

    def detect_icmp_flood(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Detect abnormally high-rate ICMP streams (Ping flood).
        """
        icmp_pkts = [p for p in packets if p.protocol == "ICMP" and p.dst_ip]
        if len(icmp_pkts) < self.icmp_min_packets:
            return []

        icmp_pkts = sorted(icmp_pkts, key=lambda p: p.timestamp)

        target_groups: Dict[str, List[PacketRecord]] = defaultdict(list)
        for p in icmp_pkts:
            target_groups[p.dst_ip].append(p)

        detections: List[Dict[str, Any]] = []

        for target_ip, pkts in target_groups.items():
            if len(pkts) < self.icmp_min_packets:
                continue

            start_idx = 0
            n = len(pkts)
            last_reported_end_ts = -1.0

            for end_idx in range(n):
                current_ts = pkts[end_idx].timestamp
                while start_idx < end_idx and (current_ts - pkts[start_idx].timestamp) > self.icmp_window_sec:
                    start_idx += 1

                window_slice = pkts[start_idx : end_idx + 1]
                window_count = len(window_slice)

                if window_count >= self.icmp_min_packets:
                    duration = max(0.01, current_ts - pkts[start_idx].timestamp)
                    pps = window_count / duration

                    if pps >= self.icmp_pps_threshold:
                        if current_ts <= last_reported_end_ts:
                            continue

                        sources = [p.src_ip for p in window_slice if p.src_ip]
                        src_counts: Dict[str, int] = defaultdict(int)
                        for s in sources:
                            src_counts[s] += 1

                        primary_src = max(src_counts.items(), key=lambda x: x[1])[0] if src_counts else "UNKNOWN"
                        unique_sources = len(src_counts)

                        icmp_types = {p.icmp_type for p in window_slice if p.icmp_type is not None}
                        confidence = "HIGH" if (pps >= self.icmp_pps_threshold * 1.5 and window_count >= self.icmp_min_packets * 1.5) else "MEDIUM"

                        desc = (
                            f"ICMP Flood detected: Target {target_ip} received {window_count} ICMP packets "
                            f"at {pps:.1f} packets/sec over {duration:.2f}s "
                            f"(Thresholds: >= {self.icmp_min_packets} pkts, >= {self.icmp_pps_threshold} pps)."
                        )

                        detections.append({
                            "detected": True,
                            "threat_type": "ICMP_FLOOD",
                            "source_ip": primary_src,
                            "destination_ip": target_ip,
                            "timestamp": round(current_ts, 4),
                            "description": desc,
                            "evidence": {
                                "icmp_packets": window_count,
                                "duration_seconds": round(duration, 3),
                                "packets_per_second": round(pps, 1),
                                "threshold_pps": self.icmp_pps_threshold,
                                "threshold_min_packets": self.icmp_min_packets,
                                "icmp_types": sorted(list(icmp_types)),
                                "unique_sources_count": unique_sources,
                            },
                            "confidence": confidence,
                        })
                        last_reported_end_ts = current_ts

        return detections
