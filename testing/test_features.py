"""
NetGuard Unit Tests - Feature Extraction & NumPy Analyzer.
Validates statistical metrics, vectorized calculations, protocol breakdowns,
TCP flag distributions, and edge-case resilience.
"""

import json
import pytest
import numpy as np

from preprocessing.packet_parser import PacketRecord
from features.numpy_analyzer import NumPyTrafficAnalyzer
from features.feature_extractor import TrafficFeatureExtractor, extract_traffic_features


class TestNumPyTrafficAnalyzer:
    """Tests for low-level vectorized NumPy calculations."""

    def test_compute_size_statistics_empty(self):
        empty_arr = np.array([], dtype=np.int64)
        stats = NumPyTrafficAnalyzer.compute_size_statistics(empty_arr)
        assert stats["total_bytes"] == 0
        assert stats["avg_packet_size"] == 0.0
        assert stats["std_packet_size"] == 0.0
        assert stats["min_packet_size"] == 0
        assert stats["max_packet_size"] == 0

    def test_compute_size_statistics_valid(self):
        sizes = np.array([100, 200, 300, 400], dtype=np.int64)
        stats = NumPyTrafficAnalyzer.compute_size_statistics(sizes)
        assert stats["total_bytes"] == 1000
        assert stats["avg_packet_size"] == 250.0
        assert stats["min_packet_size"] == 100
        assert stats["max_packet_size"] == 400
        assert stats["std_packet_size"] > 0

    def test_compute_size_percentiles(self):
        sizes = np.array(range(1, 101), dtype=np.int64)  # 1 to 100
        pcts = NumPyTrafficAnalyzer.compute_size_percentiles(sizes)
        assert "p25" in pcts
        assert "p50" in pcts
        assert "p75" in pcts
        assert "p90" in pcts
        assert "p95" in pcts
        assert "p99" in pcts
        assert pcts["p50"] == pytest.approx(50.5, 0.5)

    def test_compute_protocol_distribution(self):
        protos = np.array(["TCP", "TCP", "UDP", "ICMP", "TCP"])
        counts, pcts = NumPyTrafficAnalyzer.compute_protocol_distribution(protos)
        assert counts["TCP"] == 3
        assert counts["UDP"] == 1
        assert counts["ICMP"] == 1
        assert pcts["TCP"] == 60.0
        assert pcts["UDP"] == 20.0
        assert pcts["ICMP"] == 20.0

    def test_compute_port_frequency(self):
        ports = np.array([80, 443, 80, -1, 80, 22, 443], dtype=np.int64)
        top_ports = NumPyTrafficAnalyzer.compute_port_frequency(ports, top_n=2)
        assert len(top_ports) == 2
        assert top_ports[0]["port"] == 80
        assert top_ports[0]["count"] == 3
        assert top_ports[1]["port"] == 443
        assert top_ports[1]["count"] == 2

    def test_compute_tcp_flag_metrics(self):
        flags = np.array(["S", "SA", "PA", "F", "R", ""])
        protocols = np.array(["TCP", "TCP", "TCP", "TCP", "TCP", "UDP"])
        metrics = NumPyTrafficAnalyzer.compute_tcp_flag_metrics(flags, protocols)
        assert metrics["tcp_packets"] == 5
        assert metrics["syn_count"] == 2  # S and SA
        assert metrics["syn_only_count"] == 1  # S only
        assert metrics["syn_ack_count"] == 1  # SA
        assert metrics["ack_count"] == 2  # SA, PA
        assert metrics["fin_count"] == 1
        assert metrics["rst_count"] == 1


class TestTrafficFeatureExtractor:
    """Tests for the high-level TrafficFeatureExtractor."""

    def test_empty_packet_collection(self):
        features = extract_traffic_features([])
        assert features["summary"]["total_packets"] == 0
        assert features["summary"]["total_bytes"] == 0
        assert features["summary"]["capture_duration"] == 0.0
        assert features["summary"]["packets_per_second"] == 0.0
        assert features["protocols"]["counts"]["TCP"] == 0
        # Check JSON serializability
        serialized = json.dumps(features)
        assert isinstance(serialized, str)

    def test_single_packet(self):
        pkt = PacketRecord(
            timestamp=100.0,
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            src_port=5000,
            dst_port=80,
            protocol="TCP",
            packet_size=60,
            tcp_flags="S",
        )
        features = extract_traffic_features([pkt])
        assert features["summary"]["total_packets"] == 1
        assert features["summary"]["total_bytes"] == 60
        assert features["summary"]["unique_source_ips"] == 1
        assert features["summary"]["unique_destination_ips"] == 1
        assert features["summary"]["unique_destination_ports"] == 1
        assert features["tcp_flags"]["syn_count"] == 1
        assert features["tcp_flags"]["syn_only_count"] == 1
        assert features["protocols"]["counts"]["TCP"] == 1

    def test_mixed_protocols(self):
        pkts = [
            PacketRecord(timestamp=10.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", packet_size=100, tcp_flags="S"),
            PacketRecord(timestamp=11.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=53, protocol="UDP", packet_size=120),
            PacketRecord(timestamp=12.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=None, dst_port=None, protocol="ICMP", packet_size=80, icmp_type=8),
            PacketRecord(timestamp=13.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=None, dst_port=None, protocol="ARP", packet_size=42, arp_op=1),
        ]
        features = extract_traffic_features(pkts)
        assert features["summary"]["total_packets"] == 4
        assert features["summary"]["total_bytes"] == 342
        assert features["protocols"]["counts"]["TCP"] == 1
        assert features["protocols"]["counts"]["UDP"] == 1
        assert features["protocols"]["counts"]["ICMP"] == 1
        assert features["protocols"]["counts"]["ARP"] == 1
        assert features["protocols"]["percentages"]["TCP"] == 25.0
        assert features["summary"]["capture_duration"] == 3.0

    def test_ipv6_traffic(self):
        pkt = PacketRecord(
            timestamp=20.0,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=4433,
            dst_port=443,
            protocol="IPV6",
            packet_size=1200,
        )
        features = extract_traffic_features([pkt])
        assert features["protocols"]["counts"]["IPv6"] == 1
        assert features["summary"]["unique_source_ips"] == 1

    def test_repeated_source_ips_and_ports(self):
        pkts = [
            PacketRecord(timestamp=1.0, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=1000, dst_port=21, protocol="TCP", packet_size=50),
            PacketRecord(timestamp=1.1, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=1001, dst_port=22, protocol="TCP", packet_size=50),
            PacketRecord(timestamp=1.2, src_ip="192.168.1.100", dst_ip="192.168.1.1", src_port=1002, dst_port=23, protocol="TCP", packet_size=50),
            PacketRecord(timestamp=1.3, src_ip="192.168.1.200", dst_ip="192.168.1.1", src_port=1000, dst_port=80, protocol="TCP", packet_size=100),
        ]
        features = extract_traffic_features(pkts)
        assert features["summary"]["unique_source_ips"] == 2
        assert features["summary"]["unique_destination_ports"] == 4

        sources = features["source_traffic"]["top_sources"]
        assert len(sources) == 2
        # Most active source first
        assert sources[0]["ip"] == "192.168.1.100"
        assert sources[0]["packet_count"] == 3
        assert sources[0]["unique_dst_ports"] == 3

    def test_zero_duration_capture(self):
        # Multiple packets at exactly the same timestamp
        pkts = [
            PacketRecord(timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=80, protocol="TCP", packet_size=60),
            PacketRecord(timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=2, dst_port=80, protocol="TCP", packet_size=60),
        ]
        features = extract_traffic_features(pkts)
        assert features["summary"]["capture_duration"] == 0.0
        assert features["summary"]["packets_per_second"] == 0.0
        assert features["summary"]["bytes_per_second"] == 0.0

    def test_missing_optional_fields(self):
        pkt = PacketRecord(
            timestamp=50.0,
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol="OTHER",
            packet_size=14,
        )
        features = extract_traffic_features([pkt])
        assert features["summary"]["total_packets"] == 1
        assert features["summary"]["unique_source_ips"] == 0
        assert features["summary"]["unique_destination_ips"] == 0
        assert features["summary"]["unique_destination_ports"] == 0

    def test_json_serializability(self):
        pkts = [
            PacketRecord(timestamp=1.0 + i * 0.1, src_ip=f"10.0.0.{i % 5}", dst_ip="10.0.0.254", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=50 + i * 10, tcp_flags="S" if i % 2 == 0 else "A")
            for i in range(20)
        ]
        features = extract_traffic_features(pkts)
        json_str = json.dumps(features, indent=2)
        assert isinstance(json_str, str)
        # Deserialize back
        parsed = json.loads(json_str)
        assert parsed["summary"]["total_packets"] == 20

    def test_large_synthetic_packet_collection(self):
        # 5,000 synthetic packets to test performance and vectorization scalability
        count = 5000
        pkts = [
            PacketRecord(
                timestamp=1000.0 + i * 0.01,
                src_ip=f"192.168.1.{i % 50}",
                dst_ip="10.0.0.1",
                src_port=1024 + (i % 20000),
                dst_port=80 if i % 3 == 0 else 443,
                protocol="TCP" if i % 4 != 0 else "UDP",
                packet_size=64 if i % 2 == 0 else 1400,
                tcp_flags="S" if i % 5 == 0 else "A",
            )
            for i in range(count)
        ]
        features = extract_traffic_features(pkts)
        assert features["summary"]["total_packets"] == count
        assert features["summary"]["capture_duration"] > 0
        assert features["summary"]["packets_per_second"] > 0
        assert features["summary"]["avg_packet_size"] > 0
        assert len(features["source_traffic"]["top_sources"]) <= 10
        assert json.dumps(features) is not None
