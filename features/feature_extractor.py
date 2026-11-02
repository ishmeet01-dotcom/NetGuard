"""
NetGuard Feature Extractor Module
Extracts comprehensive statistical, protocol, TCP, source, and time-based features
from collections of PacketRecord objects using vectorized NumPy analytics.
"""

from typing import List, Dict, Any, Optional
import numpy as np

from preprocessing.packet_parser import PacketRecord
from features.numpy_analyzer import NumPyTrafficAnalyzer


class TrafficFeatureExtractor:
    """
    Extracts structured, JSON-serializable traffic features from packet streams.
    Combines high-performance NumPy vectorization with safe input validation.
    """

    def __init__(self, top_n_sources: int = 10, top_n_ports: int = 10):
        self.top_n_sources = top_n_sources
        self.top_n_ports = top_n_ports
        self.analyzer = NumPyTrafficAnalyzer()

    def extract_features(self, packets: List[PacketRecord]) -> Dict[str, Any]:
        """
        Extract complete network traffic features from a sequence of PacketRecords.
        Guarantees structured, JSON-serializable output with zero NumPy types.
        """
        if not packets:
            return self._empty_feature_set()

        # Extract parallel arrays from packet records
        n = len(packets)
        timestamps = np.empty(n, dtype=np.float64)
        packet_sizes = np.empty(n, dtype=np.int64)
        protocols = np.empty(n, dtype=object)
        src_ips = np.empty(n, dtype=object)
        dst_ips = np.empty(n, dtype=object)
        dst_ports = np.full(n, -1, dtype=np.int64)
        tcp_flags = np.empty(n, dtype=object)

        for i, p in enumerate(packets):
            timestamps[i] = float(p.timestamp) if (p.timestamp is not None and not np.isnan(p.timestamp)) else 0.0
            packet_sizes[i] = int(p.packet_size) if (p.packet_size is not None and p.packet_size >= 0) else 0
            protocols[i] = str(p.protocol).upper() if p.protocol else "OTHER"
            src_ips[i] = str(p.src_ip).strip() if p.src_ip else ""
            dst_ips[i] = str(p.dst_ip).strip() if p.dst_ip else ""
            dst_ports[i] = int(p.dst_port) if (p.dst_port is not None and 0 <= p.dst_port <= 65535) else -1
            tcp_flags[i] = str(p.tcp_flags).strip().upper() if p.tcp_flags else ""

        # 1. Size & Volume Statistics
        size_stats = self.analyzer.compute_size_statistics(packet_sizes)
        percentiles = self.analyzer.compute_size_percentiles(packet_sizes)

        # 2. Protocol Distribution
        proto_counts, proto_pcts = self.analyzer.compute_protocol_distribution(protocols)

        # 3. TCP Flag Analysis
        tcp_metrics = self.analyzer.compute_tcp_flag_metrics(tcp_flags, protocols)

        # 4. Temporal Rates
        rate_metrics = self.analyzer.compute_rate_metrics(timestamps, packet_sizes)

        # 5. Port Frequency Analysis
        top_dst_ports = self.analyzer.compute_port_frequency(dst_ports, top_n=self.top_n_ports)

        # 6. Source-Level Analytics
        top_sources, src_port_metrics = self._compute_source_features(
            src_ips, dst_ports, packet_sizes, n
        )

        # 7. Unique Entity Counts
        valid_srcs = src_ips[src_ips != ""]
        unique_src_count = int(np.unique(valid_srcs).size) if valid_srcs.size > 0 else 0

        valid_dsts = dst_ips[dst_ips != ""]
        unique_dst_count = int(np.unique(valid_dsts).size) if valid_dsts.size > 0 else 0

        valid_ports = dst_ports[(dst_ports >= 0) & (dst_ports <= 65535)]
        unique_dst_port_count = int(np.unique(valid_ports).size) if valid_ports.size > 0 else 0

        # 8. Statistical Anomaly Indicators
        anomaly_indicators = self.analyzer.compute_statistical_indicators(packet_sizes)

        return {
            "summary": {
                "total_packets": n,
                "total_bytes": size_stats["total_bytes"],
                "avg_packet_size": size_stats["avg_packet_size"],
                "std_packet_size": size_stats["std_packet_size"],
                "min_packet_size": size_stats["min_packet_size"],
                "max_packet_size": size_stats["max_packet_size"],
                "unique_source_ips": unique_src_count,
                "unique_destination_ips": unique_dst_count,
                "unique_destination_ports": unique_dst_port_count,
                "capture_duration": rate_metrics["capture_duration"],
                "packets_per_second": rate_metrics["packets_per_second"],
                "bytes_per_second": rate_metrics["bytes_per_second"],
                "first_timestamp": rate_metrics["first_timestamp"],
                "last_timestamp": rate_metrics["last_timestamp"],
            },
            "protocols": {
                "counts": {
                    "TCP": proto_counts.get("TCP", 0),
                    "UDP": proto_counts.get("UDP", 0),
                    "ICMP": proto_counts.get("ICMP", 0),
                    "ARP": proto_counts.get("ARP", 0),
                    "IPv6": proto_counts.get("IPV6", 0),
                    "OTHER": proto_counts.get("OTHER", 0),
                    **{k: v for k, v in proto_counts.items() if k not in ("TCP", "UDP", "ICMP", "ARP", "IPV6", "OTHER")}
                },
                "percentages": proto_pcts,
            },
            "tcp_flags": tcp_metrics,
            "source_traffic": {
                "top_sources": top_sources,
                "ports_probed_per_source": src_port_metrics,
            },
            "destination_ports": {
                "top_ports": top_dst_ports,
            },
            "packet_size_percentiles": percentiles,
            "statistical_indicators": anomaly_indicators,
        }

    def _compute_source_features(
        self,
        src_ips: np.ndarray,
        dst_ports: np.ndarray,
        packet_sizes: np.ndarray,
        total_packets: int
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """
        Compute per-source traffic volume, percentage share, and unique destination ports.
        """
        valid_mask = src_ips != ""
        if not np.any(valid_mask):
            return [], {}

        v_srcs = src_ips[valid_mask]
        v_ports = dst_ports[valid_mask]
        v_sizes = packet_sizes[valid_mask]

        unique_srcs, inverse, counts = np.unique(v_srcs, return_inverse=True, return_counts=True)
        bytes_per_src = np.bincount(inverse, weights=v_sizes.astype(np.float64))

        # Destination ports per source
        ports_per_source: Dict[str, int] = {}
        for ip in unique_srcs:
            ip_mask = v_srcs == ip
            src_ports = v_ports[ip_mask]
            valid_src_ports = src_ports[(src_ports >= 0) & (src_ports <= 65535)]
            unique_p = int(np.unique(valid_src_ports).size) if valid_src_ports.size > 0 else 0
            ports_per_source[str(ip)] = unique_p

        # Sort descending by packet count
        sorted_indices = np.argsort(counts)[::-1]
        top_indices = sorted_indices[:self.top_n_sources]

        top_sources = []
        for idx in top_indices:
            ip_str = str(unique_srcs[idx])
            pkt_cnt = int(counts[idx])
            pct = round((pkt_cnt / total_packets) * 100.0, 2) if total_packets > 0 else 0.0
            top_sources.append({
                "ip": ip_str,
                "packet_count": pkt_cnt,
                "total_bytes": int(bytes_per_src[idx]),
                "percentage": pct,
                "unique_dst_ports": ports_per_source.get(ip_str, 0),
            })

        return top_sources, ports_per_source

    @staticmethod
    def _empty_feature_set() -> Dict[str, Any]:
        """Return standardized empty feature representation when no packets are present."""
        return {
            "summary": {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_size": 0.0,
                "std_packet_size": 0.0,
                "min_packet_size": 0,
                "max_packet_size": 0,
                "unique_source_ips": 0,
                "unique_destination_ips": 0,
                "unique_destination_ports": 0,
                "capture_duration": 0.0,
                "packets_per_second": 0.0,
                "bytes_per_second": 0.0,
                "first_timestamp": 0.0,
                "last_timestamp": 0.0,
            },
            "protocols": {
                "counts": {
                    "TCP": 0,
                    "UDP": 0,
                    "ICMP": 0,
                    "ARP": 0,
                    "IPv6": 0,
                    "OTHER": 0,
                },
                "percentages": {},
            },
            "tcp_flags": {
                "tcp_packets": 0,
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "urg_count": 0,
                "syn_only_count": 0,
                "syn_ack_count": 0,
                "syn_to_tcp_ratio": 0.0,
            },
            "source_traffic": {
                "top_sources": [],
                "ports_probed_per_source": {},
            },
            "destination_ports": {
                "top_ports": [],
            },
            "packet_size_percentiles": {
                "p25": 0.0,
                "p50": 0.0,
                "p75": 0.0,
                "p90": 0.0,
                "p95": 0.0,
                "p99": 0.0,
            },
            "statistical_indicators": {
                "outlier_count": 0,
                "outlier_percentage": 0.0,
                "small_packet_ratio": 0.0,
                "jumbo_packet_ratio": 0.0,
            },
        }


def extract_traffic_features(packets: List[PacketRecord]) -> Dict[str, Any]:
    """Convenience module-level function to extract traffic features."""
    extractor = TrafficFeatureExtractor()
    return extractor.extract_features(packets)
