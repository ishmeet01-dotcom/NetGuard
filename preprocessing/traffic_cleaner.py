"""
NetGuard Traffic Cleaner Module
Validates, normalizes, and filters packet records prior to feature extraction.
"""

from typing import List, Tuple, Dict, Any, Optional
import math
import re
from preprocessing.packet_parser import PacketRecord

# Regex pattern for basic IPv4 validation
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
MAC_REGEX = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")


class TrafficCleaner:
    """Cleans and standardizes streams of packet records."""

    @staticmethod
    def is_valid_ipv4(ip: Optional[str]) -> bool:
        """Validate if a string is a valid IPv4 address."""
        if not ip or not isinstance(ip, str):
            return False
        ip = ip.strip()
        if not IPV4_REGEX.match(ip):
            return False
        parts = ip.split(".")
        return all(0 <= int(part) <= 255 for part in parts)

    @staticmethod
    def normalize_mac(mac: Optional[str]) -> Optional[str]:
        """Standardize MAC address to lowercase colon-separated format."""
        if not mac or not isinstance(mac, str):
            return None
        clean_mac = mac.strip().lower().replace("-", ":")
        if MAC_REGEX.match(clean_mac):
            return clean_mac
        return mac.strip().lower()

    @classmethod
    def validate_record(cls, record: PacketRecord) -> Tuple[bool, Optional[str]]:
        """
        Validate whether a packet record has viable data for analysis.
        Returns (is_valid, rejection_reason).
        """
        if not isinstance(record, PacketRecord):
            return False, "Not a PacketRecord instance"

        # Validate timestamp
        if not isinstance(record.timestamp, (int, float)) or math.isnan(record.timestamp) or math.isinf(record.timestamp):
            return False, "Invalid timestamp"
        if record.timestamp < 0:
            return False, "Negative timestamp"

        # Check packet size
        if not isinstance(record.packet_size, int) or record.packet_size < 0:
            return False, "Invalid packet size"

        # Check protocol
        if record.protocol == "MALFORMED":
            return False, "Malformed packet layer"

        # For IP-based packets, verify at least destination or source exists
        if record.protocol in ("TCP", "UDP", "ICMP", "IP"):
            if not record.src_ip and not record.dst_ip:
                return False, "Missing both source and destination IP"

        # Check port validity if present
        if record.src_port is not None and not (0 <= record.src_port <= 65535):
            return False, "Invalid source port"
        if record.dst_port is not None and not (0 <= record.dst_port <= 65535):
            return False, "Invalid destination port"

        return True, None

    @classmethod
    def clean_record(cls, record: PacketRecord) -> Optional[PacketRecord]:
        """
        Clean and normalize a single PacketRecord.
        Returns cleaned record, or None if record is unrecoverably invalid.
        """
        is_valid, _ = cls.validate_record(record)
        if not is_valid:
            return None

        # Normalize IPs
        cleaned_src_ip = record.src_ip.strip() if record.src_ip else None
        cleaned_dst_ip = record.dst_ip.strip() if record.dst_ip else None

        # Normalize MACs
        cleaned_src_mac = cls.normalize_mac(record.src_mac)
        cleaned_dst_mac = cls.normalize_mac(record.dst_mac)

        # Normalize flags
        cleaned_flags = record.tcp_flags.strip().upper() if record.tcp_flags else None

        return PacketRecord(
            timestamp=float(record.timestamp),
            src_ip=cleaned_src_ip,
            dst_ip=cleaned_dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
            protocol=record.protocol.upper() if record.protocol else "OTHER",
            packet_size=int(record.packet_size),
            payload_size=max(0, int(record.payload_size)),
            tcp_flags=cleaned_flags,
            icmp_type=record.icmp_type,
            icmp_code=record.icmp_code,
            src_mac=cleaned_src_mac,
            dst_mac=cleaned_dst_mac,
            arp_op=record.arp_op,
            raw_summary=record.raw_summary or "",
        )

    @classmethod
    def clean_batch(cls, records: List[PacketRecord]) -> Tuple[List[PacketRecord], Dict[str, Any]]:
        """
        Clean an entire list of PacketRecords.
        Returns (cleaned_records, cleaning_stats).
        """
        cleaned_records: List[PacketRecord] = []
        dropped_count = 0
        reasons: Dict[str, int] = {}

        for record in records:
            cleaned = cls.clean_record(record)
            if cleaned is not None:
                cleaned_records.append(cleaned)
            else:
                dropped_count += 1
                _, reason = cls.validate_record(record)
                reason_key = reason or "Unknown"
                reasons[reason_key] = reasons.get(reason_key, 0) + 1

        stats = {
            "total_input": len(records),
            "total_cleaned": len(cleaned_records),
            "total_dropped": dropped_count,
            "drop_reasons": reasons,
        }

        return cleaned_records, stats
