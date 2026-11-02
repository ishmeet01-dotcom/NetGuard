"""
NetGuard Risk Scoring Engine
Calculates heuristic threat risk scores (0-100) and severity levels based on
detection evidence, confidence ratings, and multi-indicator host correlation.
"""

from typing import Dict, Any, List, Optional
import numpy as np

from config import RISK_CONFIG


class RiskScorer:
    """
    Evaluates detection findings to assign calibrated risk scores and severity ratings.
    Uses evidence weighting, confidence adjustments, and np.clip.
    """

    def __init__(self, risk_config: Optional[Dict[str, Any]] = None):
        cfg = risk_config or RISK_CONFIG
        self.base_scores: Dict[str, float] = cfg.get(
            "base_scores",
            {
                "PORT_SCAN": 60.0,
                "SYN_FLOOD": 90.0,
                "UDP_FLOOD": 85.0,
                "ICMP_FLOOD": 75.0,
                "ARP_ANOMALY": 85.0,
                "STATISTICAL_ANOMALY": 40.0,
            },
        )
        self.severity_levels = cfg.get(
            "severity_levels",
            {
                "LOW": (0, 29),
                "MEDIUM": (30, 59),
                "HIGH": (60, 79),
                "CRITICAL": (80, 100),
            },
        )

    def determine_severity(self, score: float) -> str:
        """Map numerical score (0-100) to severity category."""
        clipped = float(np.clip(score, 0.0, 100.0))
        for level, (low, high) in self.severity_levels.items():
            if low <= clipped <= high:
                return level
        return "CRITICAL" if clipped >= 80.0 else "LOW"

    def score_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score and severity for a single detection record.
        Returns enriched copy of the detection.
        """
        threat_type = str(detection.get("threat_type", "UNKNOWN")).upper()
        confidence = str(detection.get("confidence", "MEDIUM")).upper()
        evidence = detection.get("evidence", {}) or {}

        # 1. Base Score
        base = float(self.base_scores.get(threat_type, 50.0))
        adjustment = 0.0
        explanations = [f"Base score: {base:.0f}"]

        # 2. Confidence Adjustment
        if confidence == "HIGH":
            adjustment += 10.0
            explanations.append("Confidence HIGH (+10)")
        elif confidence == "LOW":
            adjustment -= 15.0
            explanations.append("Confidence LOW (-15)")

        # 3. Evidence-Based Heuristics
        if threat_type == "PORT_SCAN":
            if evidence.get("is_syn_scan"):
                adjustment += 5.0
                explanations.append("SYN scan pattern (+5)")
            port_count = evidence.get("unique_ports_count", 0)
            if port_count >= 50:
                adjustment += 10.0
                explanations.append("Extensive port probing >=50 (+10)")
            elif port_count >= 25:
                adjustment += 5.0
                explanations.append("Moderate port probing >=25 (+5)")

        elif threat_type == "SYN_FLOOD":
            pps = evidence.get("packets_per_second", 0.0)
            if pps >= 150.0:
                adjustment += 5.0
                explanations.append("Severe packet rate >=150pps (+5)")
            if evidence.get("unique_sources_count", 1) > 3:
                adjustment += 5.0
                explanations.append("Distributed sources (+5)")

        elif threat_type == "UDP_FLOOD":
            pps = evidence.get("packets_per_second", 0.0)
            if pps >= 150.0:
                adjustment += 5.0
                explanations.append("Severe UDP rate >=150pps (+5)")
            if evidence.get("targeted_ports_count", 1) > 5:
                adjustment += 5.0
                explanations.append("Multiple target ports (+5)")

        elif threat_type == "ICMP_FLOOD":
            pps = evidence.get("packets_per_second", 0.0)
            if pps >= 80.0:
                adjustment += 5.0
                explanations.append("High ICMP rate >=80pps (+5)")

        elif threat_type == "ARP_ANOMALY":
            if evidence.get("is_flapping"):
                adjustment += 10.0
                explanations.append("MAC address flapping (+10)")
            delta = evidence.get("time_delta_seconds", 60.0)
            if delta <= 5.0:
                adjustment += 5.0
                explanations.append("Rapid binding flip <=5s (+5)")

        elif threat_type == "STATISTICAL_ANOMALY":
            metric = evidence.get("metric")
            if metric == "packets_per_second" and evidence.get("observed_value", 0) >= 800:
                adjustment += 15.0
                explanations.append("Extreme rate burst >=800pps (+15)")
            elif metric == "source_concentration" and evidence.get("observed_ratio", 0) >= 0.95:
                adjustment += 10.0
                explanations.append("Severe host concentration >=95% (+10)")

        raw_score = base + adjustment
        # Bound score between 0.0 and 100.0 using NumPy
        final_score = float(np.clip(raw_score, 0.0, 100.0))
        final_score = round(final_score, 1)

        severity = self.determine_severity(final_score)
        explanation_str = "; ".join(explanations) + f" => Final: {final_score:.1f} ({severity})"

        scored = dict(detection)
        scored["risk_score"] = final_score
        scored["severity"] = severity
        scored["score_explanation"] = explanation_str

        return scored

    def score_detections(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score an entire list of detections."""
        return [self.score_detection(d) for d in detections]

    def aggregate_host_risk(self, detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate risk for multiple detections affecting the same host.
        Uses a diminishing returns model to prevent runaway addition.
        Formula: max_score + 0.25 * sum(other_scores), clipped to 100.0.
        """
        if not detections:
            return {
                "overall_score": 0.0,
                "overall_severity": "LOW",
                "detection_count": 0,
            }

        scored = self.score_detections(detections)
        scores = np.array([d["risk_score"] for d in scored], dtype=np.float64)

        if scores.size == 1:
            total_score = scores[0]
        else:
            sorted_scores = np.sort(scores)[::-1]
            primary = sorted_scores[0]
            secondary_sum = np.sum(sorted_scores[1:])
            total_score = primary + (0.25 * secondary_sum)

        final_host_score = float(np.clip(total_score, 0.0, 100.0))
        final_host_score = round(final_host_score, 1)
        severity = self.determine_severity(final_host_score)

        return {
            "overall_score": final_host_score,
            "overall_severity": severity,
            "detection_count": len(detections),
            "detections": scored,
        }
