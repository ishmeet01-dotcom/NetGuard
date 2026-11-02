"""
NetGuard Unit Tests - Alert Manager.
Validates alert creation, unique ID formats, status transitions,
duplicate suppression, and multi-parameter filtering.
"""

import pytest
from alerts.alert_manager import AlertManager


class TestAlertManager:
    """Tests for AlertManager lifecycle and queries."""

    @pytest.fixture
    def manager(self):
        return AlertManager(dedup_window=5.0)

    def test_create_alert_from_detection(self, manager):
        scored_detection = {
            "threat_type": "PORT_SCAN",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "timestamp": 100.0,
            "severity": "HIGH",
            "risk_score": 75.0,
            "description": "Port scan observed",
            "evidence": {"unique_ports": 20},
        }
        alert = manager.create_alert_from_detection(scored_detection)
        assert alert is not None
        assert alert["alert_id"].startswith("ALT-")
        assert alert["source_ip"] == "192.168.1.50"
        assert alert["destination_ip"] == "192.168.1.1"
        assert alert["threat_type"] == "PORT_SCAN"
        assert alert["severity"] == "HIGH"
        assert alert["status"] == "NEW"
        assert alert["risk_score"] == 75.0

    def test_unique_alert_ids(self, manager):
        ids = set()
        for i in range(10):
            det = {
                "threat_type": f"THREAT_{i}",
                "source_ip": f"10.0.0.{i}",
                "destination_ip": "10.0.0.254",
                "timestamp": float(i),
            }
            alert = manager.create_alert_from_detection(det)
            assert alert["alert_id"] not in ids
            ids.add(alert["alert_id"])
        assert len(ids) == 10

    def test_status_update_valid(self, manager):
        det = {
            "threat_type": "SYN_FLOOD",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "timestamp": 50.0,
        }
        alert = manager.create_alert_from_detection(det)
        alert_id = alert["alert_id"]

        assert manager.update_status(alert_id, "INVESTIGATING") is True
        fetched = manager.get_alert_by_id(alert_id)
        assert fetched["status"] == "INVESTIGATING"

        assert manager.update_status(alert_id, "RESOLVED") is True
        assert manager.get_alert_by_id(alert_id)["status"] == "RESOLVED"

    def test_status_update_invalid_status_raises_error(self, manager):
        det = {
            "threat_type": "SYN_FLOOD",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "timestamp": 50.0,
        }
        alert = manager.create_alert_from_detection(det)
        with pytest.raises(ValueError):
            manager.update_status(alert["alert_id"], "INVALID_STATUS_XYZ")

    def test_duplicate_alert_suppression(self, manager):
        det1 = {
            "threat_type": "PORT_SCAN",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "timestamp": 100.0,
        }
        # Exact duplicate 1 second later (within 5.0s window)
        det2 = {
            "threat_type": "PORT_SCAN",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "timestamp": 101.0,
        }
        alert1 = manager.create_alert_from_detection(det1)
        alert2 = manager.create_alert_from_detection(det2)

        assert alert1 is not None
        assert alert2 is None  # Suppressed!
        assert len(manager.alerts) == 1

        # Event after window expires (100.0 + 6.0 = 106.0)
        det3 = {
            "threat_type": "PORT_SCAN",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "timestamp": 106.0,
        }
        alert3 = manager.create_alert_from_detection(det3)
        assert alert3 is not None
        assert len(manager.alerts) == 2

    def test_filtering_alerts(self, manager):
        manager.create_alert_from_detection({"threat_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "timestamp": 1.0})
        manager.create_alert_from_detection({"threat_type": "SYN_FLOOD", "severity": "CRITICAL", "source_ip": "10.0.0.2", "destination_ip": "10.0.0.3", "timestamp": 2.0})
        manager.create_alert_from_detection({"threat_type": "ARP_ANOMALY", "severity": "CRITICAL", "source_ip": "10.0.0.1", "destination_ip": "10.0.0.4", "timestamp": 3.0})

        # Filter by severity
        crit_alerts = manager.filter_alerts(severity="CRITICAL")
        assert len(crit_alerts) == 2

        # Filter by threat_type
        scan_alerts = manager.filter_alerts(threat_type="PORT_SCAN")
        assert len(scan_alerts) == 1

        # Filter by source_ip
        src_alerts = manager.filter_alerts(source_ip="10.0.0.1")
        assert len(src_alerts) == 2
