"""
NetGuard Unit Tests - Packet Parser, Traffic Cleaner, and PCAP Reader.
Tests parsing of TCP, UDP, ICMP, ARP, malformed packets, and PCAP streaming.
"""

import pytest
import time
from pathlib import Path

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import wrpcap

from preprocessing.packet_parser import parse_scapy_packet, PacketRecord
from preprocessing.traffic_cleaner import TrafficCleaner
from capture.pcap_reader import PCAPReader, PCAPReaderError


@pytest.fixture(scope="session")
def sample_pcap_path(tmp_path_factory) -> Path:
    """Generate a synthetic PCAP file containing diverse valid packets."""
    temp_dir = tmp_path_factory.mktemp("pcap_data")
    pcap_file = temp_dir / "synthetic_test.pcap"

    packets = [
        # TCP SYN
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / TCP(sport=50001, dport=80, flags="S"),
        # TCP SYN-ACK
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="192.168.1.1", dst="192.168.1.100")
        / TCP(sport=80, dport=50001, flags="SA"),
        # TCP ACK + Data
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="192.168.1.1")
        / TCP(sport=50001, dport=80, flags="PA")
        / b"GET /status HTTP/1.1\r\n\r\n",
        # UDP Packet (DNS)
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=43210, dport=53)
        / b"\xaa\xbb\x01\x00\x00\x01\x00\x00",
        # ICMP Echo Request
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="1.1.1.1")
        / ICMP(type=8, code=0)
        / b"PingPayload123",
        # ARP Request
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.100", hwdst="00:00:00:00:00:00", pdst="192.168.1.1"),
        # ARP Reply
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / ARP(op=2, hwsrc="66:77:88:99:aa:bb", psrc="192.168.1.1", hwdst="00:11:22:33:44:55", pdst="192.168.1.100"),
    ]

    wrpcap(str(pcap_file), packets)
    return pcap_file


class TestPacketParser:
    """Tests for scapy packet parsing logic."""

    def test_parse_tcp_syn_packet(self):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="10.0.0.5", dst="10.0.0.1")
            / TCP(sport=44332, dport=443, flags="S")
        )
        record = parse_scapy_packet(pkt)
        assert record is not None
        assert record.protocol == "TCP"
        assert record.src_ip == "10.0.0.5"
        assert record.dst_ip == "10.0.0.1"
        assert record.src_port == 44332
        assert record.dst_port == 443
        assert "S" in record.tcp_flags
        assert record.is_syn is True
        assert record.is_syn_ack is False
        assert record.src_mac == "00:11:22:33:44:55"
        assert record.dst_mac == "aa:bb:cc:dd:ee:ff"
        assert record.packet_size > 0

    def test_parse_tcp_syn_ack_packet(self):
        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.5")
            / TCP(sport=443, dport=44332, flags="SA")
        )
        record = parse_scapy_packet(pkt)
        assert record is not None
        assert record.protocol == "TCP"
        assert record.is_syn is False
        assert record.is_syn_ack is True

    def test_parse_udp_packet(self):
        payload = b"NetGuard UDP test message"
        pkt = (
            Ether()
            / IP(src="172.16.0.10", dst="172.16.0.20")
            / UDP(sport=5000, dport=5001)
            / payload
        )
        record = parse_scapy_packet(pkt)
        assert record is not None
        assert record.protocol == "UDP"
        assert record.src_ip == "172.16.0.10"
        assert record.dst_ip == "172.16.0.20"
        assert record.src_port == 5000
        assert record.dst_port == 5001
        assert record.payload_size == len(payload)

    def test_parse_icmp_echo_request(self):
        pkt = (
            Ether()
            / IP(src="192.168.1.50", dst="192.168.1.1")
            / ICMP(type=8, code=0)
        )
        record = parse_scapy_packet(pkt)
        assert record is not None
        assert record.protocol == "ICMP"
        assert record.icmp_type == 8
        assert record.icmp_code == 0
        assert record.src_ip == "192.168.1.50"
        assert record.dst_ip == "192.168.1.1"

    def test_parse_arp_packet(self):
        pkt = (
            Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, hwsrc="11:22:33:44:55:66", psrc="192.168.1.200", hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
        )
        record = parse_scapy_packet(pkt)
        assert record is not None
        assert record.protocol == "ARP"
        assert record.arp_op == 1
        assert record.src_mac == "11:22:33:44:55:66"
        assert record.src_ip == "192.168.1.200"
        assert record.dst_ip == "192.168.1.1"

    def test_parse_none_or_malformed(self):
        assert parse_scapy_packet(None) is None

        # Bare layer without IP/ARP
        bare_pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        record = parse_scapy_packet(bare_pkt)
        assert record is not None
        assert record.protocol == "OTHER"
        assert record.src_mac == "aa:bb:cc:dd:ee:ff"


class TestTrafficCleaner:
    """Tests for data validation and normalization in traffic cleaner."""

    def test_clean_valid_record(self):
        rec = PacketRecord(
            timestamp=1700000000.0,
            src_ip=" 192.168.1.10 ",
            dst_ip="192.168.1.1",
            src_port=1234,
            dst_port=80,
            protocol="tcp",
            packet_size=64,
            payload_size=10,
            tcp_flags=" s ",
            src_mac="AA-BB-CC-DD-EE-FF",
            dst_mac="11:22:33:44:55:66",
        )
        cleaned = TrafficCleaner.clean_record(rec)
        assert cleaned is not None
        assert cleaned.src_ip == "192.168.1.10"
        assert cleaned.protocol == "TCP"
        assert cleaned.tcp_flags == "S"
        assert cleaned.src_mac == "aa:bb:cc:dd:ee:ff"

    def test_reject_invalid_record(self):
        # Invalid timestamp
        bad_rec = PacketRecord(
            timestamp=float("nan"),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            packet_size=100,
        )
        assert TrafficCleaner.clean_record(bad_rec) is None

        # Negative packet size
        bad_size = PacketRecord(
            timestamp=100.0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            packet_size=-5,
        )
        assert TrafficCleaner.clean_record(bad_size) is None

    def test_clean_batch_statistics(self):
        good_rec = PacketRecord(
            timestamp=100.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            packet_size=50,
        )
        bad_rec = PacketRecord(
            timestamp=-1.0,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=80,
            protocol="TCP",
            packet_size=50,
        )
        cleaned, stats = TrafficCleaner.clean_batch([good_rec, bad_rec])
        assert len(cleaned) == 1
        assert stats["total_input"] == 2
        assert stats["total_cleaned"] == 1
        assert stats["total_dropped"] == 1


class TestPCAPReader:
    """Tests for offline PCAP streaming and batch reading."""

    def test_read_synthetic_pcap(self, sample_pcap_path):
        reader = PCAPReader()
        result = reader.read_pcap(sample_pcap_path)

        assert result["success"] is True
        assert result["total_packets"] == 7
        assert "TCP" in result["protocols"]
        assert "UDP" in result["protocols"]
        assert "ICMP" in result["protocols"]
        assert "ARP" in result["protocols"]
        assert len(result["records"]) == 7

    def test_stream_packets_generator(self, sample_pcap_path):
        reader = PCAPReader()
        streamed = list(reader.stream_packets(sample_pcap_path, max_packets=3))
        assert len(streamed) == 3
        assert isinstance(streamed[0], PacketRecord)

    def test_missing_file_raises_error(self, tmp_path):
        reader = PCAPReader()
        missing_file = tmp_path / "does_not_exist.pcap"
        with pytest.raises(FileNotFoundError):
            reader.read_pcap(missing_file)

    def test_empty_file_raises_error(self, tmp_path):
        reader = PCAPReader()
        empty_file = tmp_path / "empty.pcap"
        empty_file.touch()
        with pytest.raises(PCAPReaderError):
            reader.read_pcap(empty_file)
