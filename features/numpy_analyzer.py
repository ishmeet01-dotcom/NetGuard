"""
NetGuard NumPy Analyzer Module
Performs high-performance, vectorized traffic and statistical calculations.
"""

from typing import Dict, Any, List, Tuple, Optional
import numpy as np


class NumPyTrafficAnalyzer:
    """
    Vectorized statistical traffic analyzer using NumPy.
    Implements array computations, percentile evaluation, boolean indexing,
    broadcasting, and statistical indicators.
    """

    @staticmethod
    def compute_size_statistics(packet_sizes: np.ndarray) -> Dict[str, float]:
        """
        Compute descriptive statistics for packet sizes using vectorized NumPy methods.
        Safe against empty arrays.
        """
        if packet_sizes.size == 0:
            return {
                "total_bytes": 0,
                "avg_packet_size": 0.0,
                "std_packet_size": 0.0,
                "min_packet_size": 0,
                "max_packet_size": 0,
            }

        sizes = packet_sizes.astype(np.float64)
        total_bytes = int(np.sum(sizes))
        avg_size = float(np.mean(sizes))
        std_size = float(np.std(sizes))
        min_size = int(np.min(sizes))
        max_size = int(np.max(sizes))

        return {
            "total_bytes": total_bytes,
            "avg_packet_size": round(avg_size, 2),
            "std_packet_size": round(std_size, 2),
            "min_packet_size": min_size,
            "max_packet_size": max_size,
        }

    @staticmethod
    def compute_size_percentiles(
        packet_sizes: np.ndarray,
        percentiles: Optional[List[int]] = None
    ) -> Dict[str, float]:
        """
        Calculate empirical percentiles of packet sizes using np.percentile.
        """
        if percentiles is None:
            percentiles = [25, 50, 75, 90, 95, 99]

        if packet_sizes.size == 0:
            return {f"p{p}": 0.0 for p in percentiles}

        sizes = packet_sizes.astype(np.float64)
        # Vectorized percentile computation across all requested quantiles
        vals = np.percentile(sizes, percentiles)

        return {
            f"p{p}": float(round(val, 2))
            for p, val in zip(percentiles, vals)
        }

    @staticmethod
    def compute_protocol_distribution(
        protocols: np.ndarray
    ) -> Tuple[Dict[str, int], Dict[str, float]]:
        """
        Compute frequency and percentage of protocols using np.unique.
        """
        if protocols.size == 0:
            return {}, {}

        # np.unique with counts
        unique_protos, counts = np.unique(protocols, return_counts=True)
        total = int(np.sum(counts))

        # Vectorized percentage calculation via broadcasting
        percentages = (counts.astype(np.float64) / total) * 100.0

        proto_counts: Dict[str, int] = {
            str(proto): int(count)
            for proto, count in zip(unique_protos, counts)
        }
        proto_pcts: Dict[str, float] = {
            str(proto): float(round(pct, 2))
            for proto, pct in zip(unique_protos, percentages)
        }

        return proto_counts, proto_pcts

    @staticmethod
    def compute_port_frequency(
        ports: np.ndarray,
        top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Analyze destination port frequencies using boolean masking and np.unique.
        Filters out invalid or sentinel (-1) port values.
        """
        # Boolean indexing to filter valid ports (>= 0 and <= 65535)
        valid_mask = (ports >= 0) & (ports <= 65535)
        valid_ports = ports[valid_mask]

        if valid_ports.size == 0:
            return []

        unique_ports, counts = np.unique(valid_ports, return_counts=True)
        # Vectorized sorting descending
        sorted_indices = np.argsort(counts)[::-1]
        top_indices = sorted_indices[:top_n]

        results = []
        for idx in top_indices:
            results.append({
                "port": int(unique_ports[idx]),
                "count": int(counts[idx]),
            })
        return results

    @staticmethod
    def compute_source_traffic(
        src_ips: np.ndarray,
        packet_sizes: np.ndarray,
        top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Aggregate packet counts and total bytes per source IP using vectorized grouping.
        """
        # Boolean mask to ignore empty/sentinel IP addresses
        valid_mask = src_ips != ""
        valid_ips = src_ips[valid_mask]
        valid_sizes = packet_sizes[valid_mask]

        if valid_ips.size == 0:
            return []

        unique_ips, inverse_indices, counts = np.unique(
            valid_ips, return_inverse=True, return_counts=True
        )

        # Aggregate bytes per source using np.bincount with weights
        bytes_per_ip = np.bincount(inverse_indices, weights=valid_sizes.astype(np.float64))

        # Sort by packet counts descending
        sorted_indices = np.argsort(counts)[::-1]
        top_indices = sorted_indices[:top_n]

        results = []
        for idx in top_indices:
            results.append({
                "ip": str(unique_ips[idx]),
                "packet_count": int(counts[idx]),
                "total_bytes": int(bytes_per_ip[idx]),
            })
        return results

    @staticmethod
    def compute_rate_metrics(
        timestamps: np.ndarray,
        packet_sizes: np.ndarray
    ) -> Dict[str, float]:
        """
        Compute temporal rates: duration, packets per second (pps), and bytes per second (bps).
        Uses np.ptp (peak-to-peak) or min/max and clipping.
        """
        if timestamps.size < 2:
            duration = 0.0
            pps = float(timestamps.size)
            bps = float(np.sum(packet_sizes)) if packet_sizes.size > 0 else 0.0
            return {
                "first_timestamp": float(timestamps[0]) if timestamps.size == 1 else 0.0,
                "last_timestamp": float(timestamps[0]) if timestamps.size == 1 else 0.0,
                "capture_duration": 0.0,
                "packets_per_second": pps,
                "bytes_per_second": bps,
            }

        first_ts = float(np.min(timestamps))
        last_ts = float(np.max(timestamps))
        duration = max(0.0, last_ts - first_ts)

        total_packets = timestamps.size
        total_bytes = float(np.sum(packet_sizes))

        if duration > 0.0:
            pps = total_packets / duration
            bps = total_bytes / duration
        else:
            # Zero-duration instantaneous burst: report 0.0 rate to prevent division-by-zero
            pps = 0.0
            bps = 0.0

        return {
            "first_timestamp": round(first_ts, 4),
            "last_timestamp": round(last_ts, 4),
            "capture_duration": round(duration, 4),
            "packets_per_second": round(pps, 2),
            "bytes_per_second": round(bps, 2),
        }

    @staticmethod
    def compute_tcp_flag_metrics(
        flags_arr: np.ndarray,
        protocols: np.ndarray
    ) -> Dict[str, Any]:
        """
        Analyze TCP flag distribution using vectorized string comparisons and boolean masks.
        """
        # Boolean mask isolating TCP traffic
        is_tcp = protocols == "TCP"
        tcp_count = int(np.sum(is_tcp))

        if tcp_count == 0 or flags_arr.size == 0:
            return {
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
            }

        tcp_flags = flags_arr[is_tcp]

        # Vectorized substring detection across flag strings
        # Convert to upper and check flags
        flags_upper = np.char.upper(tcp_flags.astype(str))

        has_s = np.char.find(flags_upper, "S") >= 0
        has_a = np.char.find(flags_upper, "A") >= 0
        has_f = np.char.find(flags_upper, "F") >= 0
        has_r = np.char.find(flags_upper, "R") >= 0
        has_p = np.char.find(flags_upper, "P") >= 0
        has_u = np.char.find(flags_upper, "U") >= 0

        # Exact SYN-only (SYN without ACK/RST/FIN)
        syn_only = has_s & (~has_a) & (~has_r) & (~has_f)
        # SYN-ACK
        syn_ack = has_s & has_a

        syn_count = int(np.sum(has_s))
        ack_count = int(np.sum(has_a))
        fin_count = int(np.sum(has_f))
        rst_count = int(np.sum(has_r))
        psh_count = int(np.sum(has_p))
        urg_count = int(np.sum(has_u))
        syn_only_count = int(np.sum(syn_only))
        syn_ack_count = int(np.sum(syn_ack))

        syn_ratio = (float(syn_count) / float(tcp_count)) if tcp_count > 0 else 0.0

        return {
            "tcp_packets": tcp_count,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "psh_count": psh_count,
            "urg_count": urg_count,
            "syn_only_count": syn_only_count,
            "syn_ack_count": syn_ack_count,
            "syn_to_tcp_ratio": round(syn_ratio, 4),
        }

    @staticmethod
    def compute_statistical_indicators(
        packet_sizes: np.ndarray,
        z_threshold: float = 3.0
    ) -> Dict[str, Any]:
        """
        Identify statistical outliers and anomaly indicators using z-scores,
        broadcasting, boolean indexing, and clipping with np.clip.
        """
        if packet_sizes.size < 5:
            return {
                "outlier_count": 0,
                "outlier_percentage": 0.0,
                "small_packet_ratio": 0.0,
                "jumbo_packet_ratio": 0.0,
            }

        sizes = packet_sizes.astype(np.float64)
        mean = np.mean(sizes)
        std = np.std(sizes)

        # Broadcasting to calculate z-scores
        if std > 1e-6:
            z_scores = np.abs((sizes - mean) / std)
            # Clip z-scores to avoid extreme calculation artifacts
            z_scores = np.clip(z_scores, 0.0, 10.0)
            outliers = np.where(z_scores > z_threshold)[0]
            outlier_count = int(outliers.size)
        else:
            outlier_count = 0

        # Small packets (<= 64 bytes, characteristic of scans or floods)
        small_mask = sizes <= 64.0
        small_count = int(np.sum(small_mask))

        # Jumbo / large packets (> 1400 bytes, bulk transfers)
        jumbo_mask = sizes > 1400.0
        jumbo_count = int(np.sum(jumbo_mask))

        total = float(sizes.size)
        return {
            "outlier_count": outlier_count,
            "outlier_percentage": round((outlier_count / total) * 100.0, 2),
            "small_packet_ratio": round(small_count / total, 4),
            "jumbo_packet_ratio": round(jumbo_count / total, 4),
        }
