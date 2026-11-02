"""
NetGuard Rule Engine Module
Central orchestrator that coordinates individual detection modules, manages
time-window processing, applies activation flags, and deduplicates security findings.
"""

from typing import List, Dict, Any, Optional

from config import DETECTION_THRESHOLDS, ENABLED_DETECTORS
from preprocessing.packet_parser import PacketRecord
from detection.port_scan_detector import PortScanDetector
from detection.flood_detector import FloodDetector
from detection.arp_detector import ARPAnomalyDetector
from detection.anomaly_detector import StatisticalAnomalyDetector


class RuleEngine:
    """
    Central intrusion detection rule engine.
    Orchestrates specialized detection engines and deduplicates findings.
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, Any]] = None,
        enabled_detectors: Optional[Dict[str, bool]] = None,
    ):
        self.thresholds: Dict[str, Any] = thresholds or DETECTION_THRESHOLDS
        self.enabled_switches: Dict[str, bool] = dict(enabled_detectors or ENABLED_DETECTORS)

        # Initialize sub-detectors
        self.port_scan_detector = PortScanDetector(thresholds=self.thresholds)
        self.flood_detector = FloodDetector(thresholds=self.thresholds)
        self.arp_detector = ARPAnomalyDetector(thresholds=self.thresholds)
        self.anomaly_detector = StatisticalAnomalyDetector(thresholds=self.thresholds)

        self.duplicate_window: float = float(
            self.thresholds.get("duplicate_suppression_window_sec", 5.0)
        )

    def is_detector_enabled(self, name: str) -> bool:
        """Check if a specific detection module is active."""
        return self.enabled_switches.get(name, True)

    def set_detector_enabled(self, name: str, enabled: bool):
        """Enable or disable a specific detection module at runtime."""
        self.enabled_switches[name] = enabled

    def analyze(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Run the complete inspection pipeline across a batch of packet records.
        Returns a deduplicated, standardized list of detection dictionaries.
        """
        if not packets:
            return []

        raw_detections: List[Dict[str, Any]] = []

        # 1. Port Scan Detection
        if self.is_detector_enabled("port_scan"):
            try:
                raw_detections.extend(self.port_scan_detector.detect(packets))
            except Exception:
                pass

        # 2. Flood Detection (SYN, UDP, ICMP)
        if self.is_detector_enabled("syn_flood"):
            try:
                raw_detections.extend(self.flood_detector.detect_syn_flood(packets))
            except Exception:
                pass

        if self.is_detector_enabled("udp_flood"):
            try:
                raw_detections.extend(self.flood_detector.detect_udp_flood(packets))
            except Exception:
                pass

        if self.is_detector_enabled("icmp_flood"):
            try:
                raw_detections.extend(self.flood_detector.detect_icmp_flood(packets))
            except Exception:
                pass

        # 3. ARP Anomaly Detection
        if self.is_detector_enabled("arp_anomaly"):
            try:
                raw_detections.extend(self.arp_detector.detect(packets))
            except Exception:
                pass

        # 4. Statistical Anomaly Detection
        if self.is_detector_enabled("statistical_anomaly"):
            try:
                raw_detections.extend(self.anomaly_detector.detect(packets))
            except Exception:
                pass

        # Deduplicate detections
        deduped = self._deduplicate_detections(raw_detections)

        # Sort chronologically
        deduped.sort(key=lambda d: d.get("timestamp", 0.0))

        return deduped

    def _deduplicate_detections(
        self, detections: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Suppress duplicate alerts occurring for the same threat, source, and target
        within the duplicate suppression window.
        """
        if len(detections) <= 1:
            return detections

        unique_results: List[Dict[str, Any]] = []

        # Sort by timestamp first
        sorted_dets = sorted(detections, key=lambda d: d.get("timestamp", 0.0))

        for det in sorted_dets:
            threat = det.get("threat_type")
            src = det.get("source_ip")
            dst = det.get("destination_ip")
            ts = det.get("timestamp", 0.0)

            is_dup = False
            for existing in unique_results:
                if (
                    existing.get("threat_type") == threat
                    and existing.get("source_ip") == src
                    and existing.get("destination_ip") == dst
                    and abs(ts - existing.get("timestamp", 0.0)) <= self.duplicate_window
                ):
                    is_dup = True
                    break

            if not is_dup:
                unique_results.append(det)

        return unique_results
