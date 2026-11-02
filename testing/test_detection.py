"""
NetGuard Unit Tests - Threat Detection Engines & Rule Engine.
Comprehensive deterministic testing of Port Scan, SYN Flood, UDP Flood,
ICMP Flood, ARP Anomaly, and Statistical Anomaly detection modules.
"""

import pytest
from typing import List

from preprocessing.packet_parser import PacketRecord
from detection.port_scan_detector import PortScanDetector
from detection.flood_detector import FloodDetector
from detection.arp_detector import ARPAnomalyDetector
from detection.anomaly_detector import StatisticalAnomalyDetector
from detection.rule_engine import RuleEngine


class TestPortScanDetector:
    """Tests for PortScanDetector."""

    def test_normal_browsing_traffic_no_detection(self):
        # Accessing only 2 ports (80 and 443)
        pkts = [
            PacketRecord(timestamp=10.0 + i, src_ip="192.168.1.50", dst_ip="192.168.1.1", src_port=5000 + i, dst_port=80 if i % 2 == 0 else 443, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(10)
        ]
        detector = PortScanDetector(thresholds={"port_scan_min_ports": 15, "port_scan_window_sec": 10.0})
        results = detector.detect(pkts)
        assert len(results) == 0

    def test_scan_across_many_unique_ports_triggers_detection(self):
        # Accessing 20 unique ports on 192.168.1.1 within 2.0s
        pkts = [
            PacketRecord(timestamp=10.0 + i * 0.1, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=40000 + i, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(20)
        ]
        detector = PortScanDetector(thresholds={"port_scan_min_ports": 15, "port_scan_window_sec": 10.0})
        results = detector.detect(pkts)
        assert len(results) >= 1
        det = results[0]
        assert det["threat_type"] == "PORT_SCAN"
        assert det["source_ip"] == "192.168.1.100"
        assert det["destination_ip"] == "192.168.1.1"
        assert det["evidence"]["unique_ports_count"] >= 15
        assert det["evidence"]["is_syn_scan"] is True
        assert det["confidence"] in ("MEDIUM", "HIGH")

    def test_repeated_packets_to_same_port_no_detection(self):
        # 50 packets to only 1 port (port 80)
        pkts = [
            PacketRecord(timestamp=1.0 + i * 0.05, src_ip="192.168.1.50", dst_ip="192.168.1.1", src_port=40000 + i, dst_port=80, protocol="TCP", packet_size=60, tcp_flags="PA")
            for i in range(50)
        ]
        detector = PortScanDetector(thresholds={"port_scan_min_ports": 15, "port_scan_window_sec": 10.0})
        results = detector.detect(pkts)
        assert len(results) == 0

    def test_different_source_ips_no_single_scan_detection(self):
        # 20 different source hosts each probing 1 port
        pkts = [
            PacketRecord(timestamp=1.0 + i * 0.1, src_ip=f"10.0.0.{i+1}", dst_ip="192.168.1.1", src_port=5000, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(20)
        ]
        detector = PortScanDetector(thresholds={"port_scan_min_ports": 15, "port_scan_window_sec": 10.0})
        results = detector.detect(pkts)
        assert len(results) == 0

    def test_events_outside_time_window_no_detection(self):
        # 20 unique ports spaced 20 seconds apart (outside 10s window)
        pkts = [
            PacketRecord(timestamp=1.0 + i * 20.0, src_ip="192.168.1.50", dst_ip="192.168.1.1", src_port=5000 + i, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(20)
        ]
        detector = PortScanDetector(thresholds={"port_scan_min_ports": 15, "port_scan_window_sec": 10.0})
        results = detector.detect(pkts)
        assert len(results) == 0


class TestFloodDetector:
    """Tests for FloodDetector (SYN, UDP, and ICMP floods)."""

    def test_normal_tcp_handshake_no_syn_flood(self):
        # Normal handshakes: SYN, SYN-ACK, ACK
        pkts = []
        for i in range(15):
            t = 10.0 + i * 0.2
            pkts.append(PacketRecord(timestamp=t, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60, tcp_flags="S"))
            pkts.append(PacketRecord(timestamp=t + 0.01, src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=80, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="SA"))
            pkts.append(PacketRecord(timestamp=t + 0.02, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60, tcp_flags="A"))

        detector = FloodDetector(thresholds={"syn_flood_min_packets": 50, "syn_flood_pps_threshold": 80.0, "syn_flood_window_sec": 5.0})
        results = detector.detect_syn_flood(pkts)
        assert len(results) == 0

    def test_high_syn_only_traffic_triggers_syn_flood(self):
        # 60 SYN-only packets within 0.5s (120 pps)
        pkts = [
            PacketRecord(timestamp=10.0 + i * (0.5 / 60), src_ip="192.168.1.200", dst_ip="192.168.1.1", src_port=20000 + i, dst_port=80, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(60)
        ]
        detector = FloodDetector(thresholds={"syn_flood_min_packets": 50, "syn_flood_pps_threshold": 80.0, "syn_flood_window_sec": 5.0})
        results = detector.detect_syn_flood(pkts)
        assert len(results) >= 1
        det = results[0]
        assert det["threat_type"] == "SYN_FLOOD"
        assert det["destination_ip"] == "192.168.1.1"
        assert det["evidence"]["syn_packets"] >= 50
        assert det["evidence"]["packets_per_second"] >= 80.0

    def test_syn_ack_not_counted_as_syn_only(self):
        # 60 packets with flags="SA" (SYN-ACK)
        pkts = [
            PacketRecord(timestamp=10.0 + i * 0.01, src_ip="192.168.1.200", dst_ip="192.168.1.1", src_port=80, dst_port=20000 + i, protocol="TCP", packet_size=60, tcp_flags="SA")
            for i in range(60)
        ]
        detector = FloodDetector(thresholds={"syn_flood_min_packets": 50, "syn_flood_pps_threshold": 80.0, "syn_flood_window_sec": 5.0})
        results = detector.detect_syn_flood(pkts)
        assert len(results) == 0

    def test_syn_traffic_below_min_packets_no_flood(self):
        # 10 SYN packets at high rate (not reaching min packet count of 50)
        pkts = [
            PacketRecord(timestamp=10.0 + i * 0.001, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(10)
        ]
        detector = FloodDetector(thresholds={"syn_flood_min_packets": 50, "syn_flood_pps_threshold": 80.0, "syn_flood_window_sec": 5.0})
        results = detector.detect_syn_flood(pkts)
        assert len(results) == 0

    def test_udp_flood_detection(self):
        # 70 UDP packets within 0.5s (140 pps) targeting port 53
        pkts = [
            PacketRecord(timestamp=5.0 + i * (0.5 / 70), src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=10000 + i, dst_port=53, protocol="UDP", packet_size=512)
            for i in range(70)
        ]
        detector = FloodDetector(thresholds={"udp_flood_min_packets": 60, "udp_flood_pps_threshold": 100.0, "udp_flood_window_sec": 5.0})
        results = detector.detect_udp_flood(pkts)
        assert len(results) >= 1
        det = results[0]
        assert det["threat_type"] == "UDP_FLOOD"
        assert det["destination_ip"] == "10.0.0.1"
        assert det["evidence"]["udp_packets"] >= 60

    def test_icmp_flood_detection(self):
        # 40 ICMP Echo Requests within 0.5s (80 pps)
        pkts = [
            PacketRecord(timestamp=2.0 + i * (0.5 / 40), src_ip="192.168.1.99", dst_ip="192.168.1.1", src_port=None, dst_port=None, protocol="ICMP", packet_size=84, icmp_type=8, icmp_code=0)
            for i in range(40)
        ]
        detector = FloodDetector(thresholds={"icmp_flood_min_packets": 30, "icmp_flood_pps_threshold": 40.0, "icmp_flood_window_sec": 5.0})
        results = detector.detect_icmp_flood(pkts)
        assert len(results) >= 1
        det = results[0]
        assert det["threat_type"] == "ICMP_FLOOD"
        assert det["destination_ip"] == "192.168.1.1"
        assert det["evidence"]["icmp_packets"] >= 30


class TestARPAnomalyDetector:
    """Tests for ARPAnomalyDetector."""

    def test_normal_arp_mapping_no_detection(self):
        pkts = [
            PacketRecord(timestamp=100.0 + i * 5, src_ip="192.168.1.1", dst_ip="192.168.1.100", src_port=None, dst_port=None, protocol="ARP", packet_size=42, src_mac="00:11:22:33:44:55", arp_op=2)
            for i in range(5)
        ]
        detector = ARPAnomalyDetector(thresholds={"arp_observation_window_sec": 60.0})
        results = detector.detect(pkts)
        assert len(results) == 0

    def test_conflicting_mac_mapping_triggers_detection(self):
        pkts = [
            PacketRecord(timestamp=10.0, src_ip="192.168.1.1", dst_ip="192.168.1.100", src_port=None, dst_port=None, protocol="ARP", packet_size=42, src_mac="00:11:22:33:44:55", arp_op=2),
            # Rapid change 2 seconds later from a different MAC
            PacketRecord(timestamp=12.0, src_ip="192.168.1.1", dst_ip="192.168.1.100", src_port=None, dst_port=None, protocol="ARP", packet_size=42, src_mac="aa:bb:cc:dd:ee:ff", arp_op=2),
        ]
        detector = ARPAnomalyDetector(thresholds={"arp_observation_window_sec": 60.0})
        results = detector.detect(pkts)
        assert len(results) == 1
        det = results[0]
        assert det["threat_type"] == "ARP_ANOMALY"
        assert det["source_ip"] == "192.168.1.1"
        assert det["evidence"]["previous_mac"] == "00:11:22:33:44:55"
        assert det["evidence"]["new_mac"] == "aa:bb:cc:dd:ee:ff"
        assert det["evidence"]["time_delta_seconds"] == 2.0

    def test_unrelated_ip_addresses_no_detection(self):
        pkts = [
            PacketRecord(timestamp=10.0, src_ip="192.168.1.1", dst_ip="192.168.1.100", src_port=None, dst_port=None, protocol="ARP", packet_size=42, src_mac="00:11:22:33:44:55", arp_op=2),
            PacketRecord(timestamp=11.0, src_ip="192.168.1.2", dst_ip="192.168.1.100", src_port=None, dst_port=None, protocol="ARP", packet_size=42, src_mac="aa:bb:cc:dd:ee:ff", arp_op=2),
        ]
        detector = ARPAnomalyDetector(thresholds={"arp_observation_window_sec": 60.0})
        results = detector.detect(pkts)
        assert len(results) == 0


class TestStatisticalAnomalyDetector:
    """Tests for StatisticalAnomalyDetector."""

    def test_insufficient_samples_no_detection(self):
        # 10 packets is fewer than min_samples (30)
        pkts = [
            PacketRecord(timestamp=1.0 + i, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", packet_size=60)
            for i in range(10)
        ]
        detector = StatisticalAnomalyDetector(thresholds={"anomaly_min_samples": 30})
        results = detector.detect(pkts)
        assert len(results) == 0

    def test_empty_input_handled_safely(self):
        detector = StatisticalAnomalyDetector()
        assert detector.detect([]) == []

    def test_high_rate_burst_anomaly(self):
        # 50 packets within 0.05 seconds -> 1000 pps (threshold 500 pps)
        pkts = [
            PacketRecord(timestamp=10.0 + i * 0.001, src_ip="192.168.1.10", dst_ip="192.168.1.1", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60)
            for i in range(50)
        ]
        detector = StatisticalAnomalyDetector(thresholds={"anomaly_min_samples": 30, "anomaly_rate_threshold_pps": 500.0})
        # duration is 0.049s, which is < 0.1s; let's space across 0.2s
        pkts = [
            PacketRecord(timestamp=10.0 + i * (0.2 / 150), src_ip="192.168.1.10", dst_ip="192.168.1.1", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60)
            for i in range(150)
        ]
        results = detector.detect(pkts)
        rate_anomalies = [r for r in results if r["evidence"].get("metric") == "packets_per_second"]
        assert len(rate_anomalies) >= 1
        assert rate_anomalies[0]["evidence"]["observed_value"] >= 500.0

    def test_source_concentration_anomaly(self):
        # 95 packets from 10.0.0.1, 5 packets from 10.0.0.2 (total 100 packets, concentration = 95%)
        pkts = [
            PacketRecord(timestamp=10.0 + i * 0.1, src_ip="10.0.0.1", dst_ip="10.0.0.254", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=60)
            for i in range(95)
        ] + [
            PacketRecord(timestamp=10.0 + i * 0.1, src_ip="10.0.0.2", dst_ip="10.0.0.254", src_port=2000 + i, dst_port=80, protocol="TCP", packet_size=60)
            for i in range(5)
        ]
        detector = StatisticalAnomalyDetector(thresholds={"anomaly_min_samples": 30, "anomaly_source_concentration_ratio": 0.90, "anomaly_rate_threshold_pps": 1000.0})
        results = detector.detect(pkts)
        conc_anomalies = [r for r in results if r["evidence"].get("metric") == "source_concentration"]
        assert len(conc_anomalies) >= 1
        assert conc_anomalies[0]["evidence"]["dominant_source"] == "10.0.0.1"


class TestRuleEngine:
    """Tests for central RuleEngine orchestration, activation, and deduplication."""

    def test_empty_traffic_input(self):
        engine = RuleEngine()
        assert engine.analyze([]) == []

    def test_disabled_detector_not_invoked(self):
        # Generate port scan traffic
        pkts = [
            PacketRecord(timestamp=1.0 + i * 0.1, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=40000 + i, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(20)
        ]
        # Disable port_scan
        engine = RuleEngine(enabled_detectors={"port_scan": False, "syn_flood": True, "udp_flood": True, "icmp_flood": True, "arp_anomaly": True, "statistical_anomaly": True})
        results = engine.analyze(pkts)
        port_scan_dets = [r for r in results if r["threat_type"] == "PORT_SCAN"]
        assert len(port_scan_dets) == 0

    def test_all_detectors_enabled_schema_verification(self):
        # Generate a port scan
        pkts = [
            PacketRecord(timestamp=1.0 + i * 0.1, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=40000 + i, dst_port=1000 + i, protocol="TCP", packet_size=60, tcp_flags="S")
            for i in range(20)
        ]
        engine = RuleEngine()
        results = engine.analyze(pkts)
        assert len(results) >= 1
        res = results[0]

        # Verify standardized schema keys
        required_keys = {"detected", "threat_type", "source_ip", "destination_ip", "timestamp", "description", "evidence", "confidence"}
        assert required_keys.issubset(res.keys())
        assert res["detected"] is True
        assert res["confidence"] in ("LOW", "MEDIUM", "HIGH")

    def test_duplicate_alert_suppression(self):
        engine = RuleEngine(thresholds={"duplicate_suppression_window_sec": 5.0})
        # Two identical events 1 second apart
        dets = [
            {
                "detected": True,
                "threat_type": "PORT_SCAN",
                "source_ip": "192.168.1.100",
                "destination_ip": "192.168.1.1",
                "timestamp": 10.0,
                "description": "Scan 1",
                "evidence": {},
                "confidence": "MEDIUM",
            },
            {
                "detected": True,
                "threat_type": "PORT_SCAN",
                "source_ip": "192.168.1.100",
                "destination_ip": "192.168.1.1",
                "timestamp": 11.0,  # Within 5.0s window
                "description": "Scan 2",
                "evidence": {},
                "confidence": "MEDIUM",
            },
        ]
        deduped = engine._deduplicate_detections(dets)
        assert len(deduped) == 1
        assert deduped[0]["timestamp"] == 10.0
