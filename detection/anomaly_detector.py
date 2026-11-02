"""
NetGuard Statistical Anomaly Detector Module
Evaluates traffic against statistical baselines to identify anomalous distributions,
unusual packet-size variance, burst rates, and extreme source concentration.
"""

from typing import List, Dict, Any, Optional

from config import DETECTION_THRESHOLDS
from preprocessing.packet_parser import PacketRecord
from features.feature_extractor import extract_traffic_features


class StatisticalAnomalyDetector:
    """
    Identifies statistical deviations in packet traffic.
    Treats findings as suspicious indicators, not confirmed attacks.
    """

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        cfg = thresholds or DETECTION_THRESHOLDS
        self.z_threshold: float = float(cfg.get("anomaly_z_score_threshold", 3.0))
        self.min_samples: int = int(cfg.get("anomaly_min_samples", 30))
        self.rate_threshold_pps: float = float(cfg.get("anomaly_rate_threshold_pps", 500.0))
        self.concentration_ratio: float = float(cfg.get("anomaly_source_concentration_ratio", 0.90))

    def detect(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Analyze traffic for statistical anomalies.
        Returns a list of standardized detection dictionaries.
        """
        if not packets or len(packets) < self.min_samples:
            return []

        features = extract_traffic_features(packets)
        summary = features["summary"]
        indicators = features["statistical_indicators"]
        top_sources = features["source_traffic"]["top_sources"]

        total_pkts = summary["total_packets"]
        pps = summary["packets_per_second"]
        duration = summary["capture_duration"]
        latest_ts = summary["last_timestamp"]

        detections: List[Dict[str, Any]] = []

        # 1. Packet Rate Burst Anomaly
        if duration > 0.1 and pps >= self.rate_threshold_pps:
            desc = (
                f"Statistical rate anomaly: Observed traffic rate of {pps:.1f} packets/sec "
                f"exceeds statistical threshold ({self.rate_threshold_pps:.1f} pps) across {duration:.2f}s."
            )
            dominant_src = top_sources[0]["ip"] if top_sources else "DISTRIBUTED"
            detections.append({
                "detected": True,
                "threat_type": "STATISTICAL_ANOMALY",
                "source_ip": dominant_src,
                "destination_ip": "NETWORK_WIDE",
                "timestamp": round(latest_ts, 4),
                "description": desc,
                "evidence": {
                    "metric": "packets_per_second",
                    "observed_value": round(pps, 1),
                    "threshold_value": self.rate_threshold_pps,
                    "duration_seconds": round(duration, 3),
                    "total_packets": total_pkts,
                },
                "confidence": "MEDIUM" if pps >= (self.rate_threshold_pps * 1.5) else "LOW",
            })

        # 2. Extreme Packet Size Variance / Outliers
        outlier_pct = indicators.get("outlier_percentage", 0.0)
        outlier_count = indicators.get("outlier_count", 0)
        if outlier_count >= 5 and outlier_pct >= 8.0:
            desc = (
                f"Statistical packet-size anomaly: {outlier_count} packets ({outlier_pct:.1f}%) "
                f"deviate significantly beyond {self.z_threshold} standard deviations from mean "
                f"({summary['avg_packet_size']}B ± {summary['std_packet_size']}B)."
            )
            detections.append({
                "detected": True,
                "threat_type": "STATISTICAL_ANOMALY",
                "source_ip": top_sources[0]["ip"] if top_sources else "MULTIPLE",
                "destination_ip": "NETWORK_WIDE",
                "timestamp": round(latest_ts, 4),
                "description": desc,
                "evidence": {
                    "metric": "packet_size_outliers",
                    "outlier_count": outlier_count,
                    "outlier_percentage": outlier_pct,
                    "z_score_threshold": self.z_threshold,
                    "avg_packet_size": summary["avg_packet_size"],
                    "std_packet_size": summary["std_packet_size"],
                },
                "confidence": "MEDIUM" if outlier_pct >= 15.0 else "LOW",
            })

        # 3. Disproportionate Source Traffic Concentration
        if top_sources and total_pkts >= self.min_samples:
            dominant = top_sources[0]
            dom_pct = dominant.get("percentage", 0.0) / 100.0
            if dom_pct >= self.concentration_ratio and len(top_sources) > 1:
                desc = (
                    f"Statistical traffic concentration anomaly: Single host {dominant['ip']} "
                    f"generated {dominant['percentage']:.1f}% of all observed network traffic "
                    f"({dominant['packet_count']}/{total_pkts} packets)."
                )
                detections.append({
                    "detected": True,
                    "threat_type": "STATISTICAL_ANOMALY",
                    "source_ip": dominant["ip"],
                    "destination_ip": "NETWORK_WIDE",
                    "timestamp": round(latest_ts, 4),
                    "description": desc,
                    "evidence": {
                        "metric": "source_concentration",
                        "dominant_source": dominant["ip"],
                        "observed_ratio": round(dom_pct, 4),
                        "threshold_ratio": self.concentration_ratio,
                        "dominant_packets": dominant["packet_count"],
                        "total_packets": total_pkts,
                    },
                    "confidence": "MEDIUM" if dom_pct >= 0.95 else "LOW",
                })

        return detections
