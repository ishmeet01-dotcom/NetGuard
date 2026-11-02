"""
NetGuard Unit Tests - Risk Scoring Engine.
Validates calibrated risk score calculations, evidence modifiers,
confidence adjustments, boundary clipping, and multi-indicator host aggregation.
"""

import pytest
from scoring.risk_scorer import RiskScorer


class TestRiskScorer:
    """Tests for RiskScorer heuristics and severity classification."""

    @pytest.fixture
    def scorer(self):
        return RiskScorer()

    def test_score_every_threat_type(self, scorer):
        threats = [
            ("PORT_SCAN", 60.0, "HIGH"),
            ("SYN_FLOOD", 90.0, "CRITICAL"),
            ("UDP_FLOOD", 85.0, "CRITICAL"),
            ("ICMP_FLOOD", 75.0, "HIGH"),
            ("ARP_ANOMALY", 85.0, "CRITICAL"),
            ("STATISTICAL_ANOMALY", 40.0, "MEDIUM"),
        ]
        for threat_type, expected_base, expected_sev in threats:
            detection = {
                "detected": True,
                "threat_type": threat_type,
                "confidence": "MEDIUM",
                "evidence": {},
            }
            scored = scorer.score_detection(detection)
            assert scored["risk_score"] == pytest.approx(expected_base, 0.1)
            assert scored["severity"] == expected_sev
            assert "score_explanation" in scored

    def test_score_clipping_bounds(self, scorer):
        # Extreme negative adjustment should clip to 0.0
        low_det = {
            "threat_type": "STATISTICAL_ANOMALY",
            "confidence": "LOW",
            "evidence": {},
        }
        scored_low = scorer.score_detection(low_det)
        assert 0.0 <= scored_low["risk_score"] <= 100.0

        # Extreme positive adjustment should clip to 100.0
        high_det = {
            "threat_type": "SYN_FLOOD",
            "confidence": "HIGH",
            "evidence": {"packets_per_second": 500.0, "unique_sources_count": 10},
        }
        scored_high = scorer.score_detection(high_det)
        assert scored_high["risk_score"] <= 100.0
        assert scored_high["risk_score"] == 100.0
        assert scored_high["severity"] == "CRITICAL"

    def test_confidence_adjustments(self, scorer):
        base_det = {"threat_type": "PORT_SCAN", "evidence": {}}

        med_det = scorer.score_detection({**base_det, "confidence": "MEDIUM"})
        high_det = scorer.score_detection({**base_det, "confidence": "HIGH"})
        low_det = scorer.score_detection({**base_det, "confidence": "LOW"})

        assert med_det["risk_score"] == 60.0
        assert high_det["risk_score"] == 70.0  # +10
        assert low_det["risk_score"] == 45.0   # -15

    def test_severity_boundaries(self, scorer):
        assert scorer.determine_severity(0.0) == "LOW"
        assert scorer.determine_severity(29.0) == "LOW"
        assert scorer.determine_severity(30.0) == "MEDIUM"
        assert scorer.determine_severity(59.0) == "MEDIUM"
        assert scorer.determine_severity(60.0) == "HIGH"
        assert scorer.determine_severity(79.0) == "HIGH"
        assert scorer.determine_severity(80.0) == "CRITICAL"
        assert scorer.determine_severity(100.0) == "CRITICAL"

    def test_missing_or_empty_evidence(self, scorer):
        det = {"threat_type": "UDP_FLOOD", "confidence": "MEDIUM", "evidence": None}
        scored = scorer.score_detection(det)
        assert scored["risk_score"] == 85.0
        assert scored["severity"] == "CRITICAL"

    def test_multi_indicator_host_aggregation(self, scorer):
        detections = [
            {"threat_type": "PORT_SCAN", "confidence": "MEDIUM", "evidence": {}},     # 60
            {"threat_type": "ARP_ANOMALY", "confidence": "MEDIUM", "evidence": {}},   # 85
        ]
        host_risk = scorer.aggregate_host_risk(detections)
        assert host_risk["detection_count"] == 2
        # Primary is 85, secondary is 60. 85 + 0.25*60 = 100.0
        assert host_risk["overall_score"] == 100.0
        assert host_risk["overall_severity"] == "CRITICAL"

    def test_empty_host_risk_aggregation(self, scorer):
        host_risk = scorer.aggregate_host_risk([])
        assert host_risk["overall_score"] == 0.0
        assert host_risk["overall_severity"] == "LOW"
        assert host_risk["detection_count"] == 0
