"""
NetGuard Packet Parser Module
Safely extracts standardized network features from raw Scapy packets.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import time

# Scapy layer imports
try:
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet
except ImportError:
    # Graceful fallback for non-scapy environments or synthetic testing
    Ether = ARP = IP = TCP = UDP = ICMP = IPv6 = Packet = None


@dataclass
class PacketRecord:
    """Standardized representation of an inspected network packet."""
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP, ARP, IPv6, OTHER
    packet_size: int
    payload_size: int = 0
    tcp_flags: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    arp_op: Optional[int] = None  # 1 for request, 2 for reply
    raw_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a JSON-serializable dictionary."""
        return asdict(self)

    @property
    def is_syn(self) -> bool:
        """Check if TCP packet has SYN flag set without ACK."""
        if self.protocol == "TCP" and self.tcp_flags:
            flags = self.tcp_flags.upper()
            return "S" in flags and "A" not in flags
        return False

    @property
    def is_syn_ack(self) -> bool:
        """Check if TCP packet has both SYN and ACK flags set."""
        if self.protocol == "TCP" and self.tcp_flags:
            flags = self.tcp_flags.upper()
            return "S" in flags and "A" in flags
        return False

    @property
    def is_rst(self) -> bool:
        """Check if TCP packet has RST flag set."""
        if self.protocol == "TCP" and self.tcp_flags:
            return "R" in self.tcp_flags.upper()
        return False

    @property
    def is_fin(self) -> bool:
        """Check if TCP packet has FIN flag set."""
        if self.protocol == "TCP" and self.tcp_flags:
            return "F" in self.tcp_flags.upper()
        return False


def parse_scapy_packet(packet) -> Optional[PacketRecord]:
    """
    Safely parse a Scapy packet into a structured PacketRecord.
    Handles missing layers, IPv4/IPv6, ARP, TCP, UDP, ICMP, and malformed packets.
    """
    if packet is None:
        return None

    try:
        # Determine packet timestamp
        pkt_time: float
        if hasattr(packet, "time") and packet.time is not None:
            try:
                pkt_time = float(packet.time)
            except (ValueError, TypeError):
                pkt_time = time.time()
        else:
            pkt_time = time.time()

        # Determine packet size
        try:
            pkt_size = len(packet)
        except Exception:
            pkt_size = 0

        # L2 Ethernet Header extraction
        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None
        if Ether is not None and packet.haslayer(Ether):
            try:
                eth = packet[Ether]
                src_mac = str(eth.src).lower() if hasattr(eth, "src") and eth.src else None
                dst_mac = str(eth.dst).lower() if hasattr(eth, "dst") and eth.dst else None
            except Exception:
                pass

        # Check for ARP
        if ARP is not None and packet.haslayer(ARP):
            try:
                arp = packet[ARP]
                psrc = str(arp.psrc) if hasattr(arp, "psrc") else None
                pdst = str(arp.pdst) if hasattr(arp, "pdst") else None
                hwsrc = str(arp.hwsrc).lower() if hasattr(arp, "hwsrc") else src_mac
                hwdst = str(arp.hwdst).lower() if hasattr(arp, "hwdst") else dst_mac
                op = int(arp.op) if hasattr(arp, "op") else None

                return PacketRecord(
                    timestamp=pkt_time,
                    src_ip=psrc,
                    dst_ip=pdst,
                    src_port=None,
                    dst_port=None,
                    protocol="ARP",
                    packet_size=pkt_size,
                    payload_size=0,
                    tcp_flags=None,
                    icmp_type=None,
                    icmp_code=None,
                    src_mac=hwsrc,
                    dst_mac=hwdst,
                    arp_op=op,
                    raw_summary=f"ARP op={op} {hwsrc} ({psrc}) -> {hwdst} ({pdst})",
                )
            except Exception:
                pass

        # L3 IP extraction (IPv4 or IPv6)
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        protocol_str: str = "OTHER"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None
        payload_size: int = 0

        has_ip = IP is not None and packet.haslayer(IP)
        has_ipv6 = IPv6 is not None and packet.haslayer(IPv6)

        if has_ip:
            ip = packet[IP]
            src_ip = str(ip.src) if hasattr(ip, "src") else None
            dst_ip = str(ip.dst) if hasattr(ip, "dst") else None
            protocol_str = "IP"
        elif has_ipv6:
            ip6 = packet[IPv6]
            src_ip = str(ip6.src) if hasattr(ip6, "src") else None
            dst_ip = str(ip6.dst) if hasattr(ip6, "dst") else None
            protocol_str = "IPv6"

        # L4 Protocols
        if TCP is not None and packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol_str = "TCP"
            try:
                src_port = int(tcp.sport) if hasattr(tcp, "sport") else None
                dst_port = int(tcp.dport) if hasattr(tcp, "dport") else None
                if hasattr(tcp, "flags"):
                    tcp_flags = str(tcp.flags)
                if hasattr(tcp, "payload"):
                    payload_size = len(tcp.payload)
            except Exception:
                pass

        elif UDP is not None and packet.haslayer(UDP):
            udp = packet[UDP]
            protocol_str = "UDP"
            try:
                src_port = int(udp.sport) if hasattr(udp, "sport") else None
                dst_port = int(udp.dport) if hasattr(udp, "dport") else None
                if hasattr(udp, "payload"):
                    payload_size = len(udp.payload)
            except Exception:
                pass

        elif ICMP is not None and packet.haslayer(ICMP):
            icmp = packet[ICMP]
            protocol_str = "ICMP"
            try:
                icmp_type = int(icmp.type) if hasattr(icmp, "type") else None
                icmp_code = int(icmp.code) if hasattr(icmp, "code") else None
                if hasattr(icmp, "payload"):
                    payload_size = len(icmp.payload)
            except Exception:
                pass

        # Build raw summary representation safely
        try:
            summary = packet.summary() if hasattr(packet, "summary") else f"{protocol_str} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        except Exception:
            summary = f"{protocol_str} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        return PacketRecord(
            timestamp=pkt_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_str,
            packet_size=pkt_size,
            payload_size=payload_size,
            tcp_flags=tcp_flags,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            src_mac=src_mac,
            dst_mac=dst_mac,
            arp_op=None,
            raw_summary=summary,
        )

    except Exception as exc:
        # Avoid crashing on malformed or unexpected packet structures
        return PacketRecord(
            timestamp=time.time(),
            src_ip=None,
            dst_ip=None,
            src_port=None,
            dst_port=None,
            protocol="MALFORMED",
            packet_size=0,
            payload_size=0,
            tcp_flags=None,
            icmp_type=None,
            icmp_code=None,
            src_mac=None,
            dst_mac=None,
            arp_op=None,
            raw_summary=f"ParseError: {str(exc)}",
        )
