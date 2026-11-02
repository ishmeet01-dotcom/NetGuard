"""
NetGuard Unit Tests - Flask REST API.
Validates all REST endpoints, query filters, PCAP file upload validations,
status updates, and error handling.
"""

import io
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from dashboard.app import create_app
from database.db import DatabaseManager
from capture.monitor_manager import MonitorManager


@pytest.fixture
def app_and_client(tmp_path):
    """Create a Flask test client backed by temporary isolated database and monitor."""
    temp_db = DatabaseManager(db_path=tmp_path / "test_api.db")
    monitor = MonitorManager(db_manager=temp_db)
    app = create_app(db_manager=temp_db, monitor_manager=monitor)
    app.config["TESTING"] = True
    return app, app.test_client(), temp_db, monitor


class TestFlaskAPI:
    """Tests for REST API endpoints and input validation."""

    def test_get_status_endpoint(self, app_and_client):
        _, client, _, _ = app_and_client
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["status"] == "online"
        assert "monitoring" in data
        assert "counts" in data

    def test_get_interfaces_endpoint(self, app_and_client):
        _, client, _, _ = app_and_client
        res = client.get("/api/interfaces")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert isinstance(data["interfaces"], list)

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_start_and_stop_monitor_api(self, mock_start, app_and_client):
        _, client, _, monitor = app_and_client

        # Start monitoring
        res_start = client.post("/api/monitor/start", json={"interface": None})
        assert res_start.status_code == 200
        assert res_start.get_json()["success"] is True

        # Conflict on duplicate start
        res_dup = client.post("/api/monitor/start", json={})
        assert res_dup.status_code == 409

        # Stop monitoring
        res_stop = client.post("/api/monitor/stop")
        assert res_stop.status_code == 200
        assert res_stop.get_json()["success"] is True

    def test_start_monitor_invalid_interface(self, app_and_client):
        _, client, _, _ = app_and_client
        res = client.post("/api/monitor/start", json={"interface": "completely_invalid_interface_xyz"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_get_statistics_endpoints(self, app_and_client):
        _, client, db, _ = app_and_client

        # Current live stats
        res_curr = client.get("/api/statistics")
        assert res_curr.status_code == 200
        assert "total_packets" in res_curr.get_json()

        # Seed historical stat
        db.save_network_statistics({
            "timestamp": 100.0,
            "total_packets": 200,
            "total_bytes": 15000,
            "packets_per_second": 20.0,
            "bytes_per_second": 1500.0,
            "protocols": {"TCP": 200},
        })

        res_hist = client.get("/api/statistics/history")
        assert res_hist.status_code == 200
        hist_data = res_hist.get_json()
        assert hist_data["success"] is True
        assert hist_data["count"] == 1

    def test_traffic_endpoint(self, app_and_client):
        _, client, _, _ = app_and_client
        res = client.get("/api/traffic?limit=10&offset=0")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert isinstance(data["records"], list)

    def test_alerts_endpoints_and_status_update(self, app_and_client):
        _, client, db, _ = app_and_client

        # Seed alert
        alert = {
            "alert_id": "ALT-API01",
            "timestamp": 123.45,
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "risk_score": 70.0,
            "status": "NEW",
            "description": "Port scan alert",
            "evidence": {"ports": 20},
        }
        db.insert_alert(alert)

        # List alerts
        res_list = client.get("/api/alerts?severity=HIGH")
        assert res_list.status_code == 200
        assert len(res_list.get_json()["alerts"]) == 1

        # Get alert by ID
        res_detail = client.get("/api/alerts/ALT-API01")
        assert res_detail.status_code == 200
        assert res_detail.get_json()["alert"]["source_ip"] == "10.0.0.5"

        # Missing alert detail -> 404
        res_missing = client.get("/api/alerts/ALT-NONEXISTENT")
        assert res_missing.status_code == 404

        # Update status -> Valid
        res_update = client.patch("/api/alerts/ALT-API01/status", json={"status": "INVESTIGATING"})
        assert res_update.status_code == 200
        assert res_update.get_json()["status"] == "INVESTIGATING"

        # Update status -> Invalid enum value -> 400
        res_invalid = client.patch("/api/alerts/ALT-API01/status", json={"status": "INVALID_STATUS"})
        assert res_invalid.status_code == 400

    def test_pcap_upload_validation_missing_file(self, app_and_client):
        _, client, _, _ = app_and_client
        res = client.post("/api/analyze/pcap")
        assert res.status_code == 400
        assert "No file" in res.get_json()["error"]

    def test_pcap_upload_invalid_extension(self, app_and_client):
        _, client, _, _ = app_and_client
        data = {"file": (io.BytesIO(b"fake data"), "malicious.exe")}
        res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
        assert res.status_code == 400
        assert "Invalid file extension" in res.get_json()["error"]

    def test_pcap_upload_successful_analysis(self, app_and_client):
        _, client, _, _ = app_and_client
        # Read the genuine synthetic sample_test.pcap file
        sample_path = Path("samples/sample_test.pcap")
        if sample_path.exists():
            with open(sample_path, "rb") as f:
                pcap_bytes = f.read()

            data = {"file": (io.BytesIO(pcap_bytes), "sample_test.pcap")}
            res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
            assert res.status_code == 200
            json_res = res.get_json()
            assert json_res["success"] is True
            assert json_res["total_packets"] == 10
            assert "summary" in json_res
