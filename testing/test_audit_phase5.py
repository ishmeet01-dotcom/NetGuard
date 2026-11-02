"""
NetGuard Phase 5 Audit & Hardening Test Suite.
Validates PCAP upload security, magic byte signature checks, directory traversal safeguards,
REST API parameter filtering, thread lifecycles, and queue overflow behaviors.
"""

import io
import time
from pathlib import Path
import pytest
from unittest.mock import patch

from config import SERVER_HOST, MAX_PCAP_UPLOAD_BYTES
from dashboard.app import create_app
from database.db import DatabaseManager
from capture.monitor_manager import MonitorManager
from preprocessing.packet_parser import PacketRecord


@pytest.fixture
def audit_app_and_client(tmp_path):
    """Create a test client backed by temporary isolated database and monitor."""
    temp_db = DatabaseManager(db_path=tmp_path / "audit_test.db")
    monitor = MonitorManager(db_manager=temp_db)
    app = create_app(db_manager=temp_db, monitor_manager=monitor)
    app.config["TESTING"] = True
    return app, app.test_client(), temp_db, monitor


class TestPCAPUploadSecurityAudit:
    """Audit tests for Section 1: PCAP Upload Security."""

    def test_reject_extension_signature_mismatch(self, audit_app_and_client):
        """Reject non-PCAP content masquerading as .pcap extension."""
        _, client, _, _ = audit_app_and_client
        fake_content = b"This is plain text, not a genuine PCAP file!"
        data = {"file": (io.BytesIO(fake_content), "fake_capture.pcap")}
        res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
        assert res.status_code == 400
        assert "Invalid file signature" in res.get_json()["error"]

    def test_oversized_upload_rejection(self, audit_app_and_client):
        """Reject file uploads exceeding the configured maximum size with HTTP 413."""
        _, client, _, _ = audit_app_and_client
        # Generate content exceeding MAX_PCAP_UPLOAD_BYTES (10MB)
        oversized_bytes = b"\xd4\xc3\xb2\xa1" + (b"\x00" * (MAX_PCAP_UPLOAD_BYTES + 1024))
        data = {"file": (io.BytesIO(oversized_bytes), "huge.pcap")}
        res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
        assert res.status_code == 413
        assert "exceeds maximum upload limit" in res.get_json()["error"]

    def test_filename_path_traversal_neutralized(self, audit_app_and_client):
        """Confirm that malicious client filename paths cannot escape temp sandbox."""
        _, client, _, _ = audit_app_and_client
        # Malicious filename attempting relative traversal
        traversal_name = "../../../../windows/system32/cmd.pcap"
        sample_path = Path("samples/sample_test.pcap")
        with open(sample_path, "rb") as f:
            valid_pcap = f.read()

        data = {"file": (io.BytesIO(valid_pcap), traversal_name)}
        res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
        assert res.status_code == 200
        # Returned filename is stripped to basename
        assert res.get_json()["filename"] == "cmd.pcap"

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_pcap_upload_does_not_interrupt_live_monitoring(self, mock_start, audit_app_and_client):
        """Verify upload analysis does not modify or terminate an active live monitoring session."""
        _, client, _, monitor = audit_app_and_client
        monitor.start_monitoring(interface=None)
        assert monitor.is_monitoring is True

        sample_path = Path("samples/sample_test.pcap")
        with open(sample_path, "rb") as f:
            valid_pcap = f.read()

        data = {"file": (io.BytesIO(valid_pcap), "sample.pcap")}
        res = client.post("/api/analyze/pcap", data=data, content_type="multipart/form-data")
        assert res.status_code == 200

        # Live monitoring state is preserved intact
        assert monitor.is_monitoring is True
        monitor.stop_monitoring()


class TestRESTAPICompletenessAudit:
    """Audit tests for Section 2: REST API Completeness & Input Validation."""

    def test_api_binds_to_localhost_by_default(self):
        """Verify API server host defaults to 127.0.0.1, never 0.0.0.0."""
        assert SERVER_HOST == "127.0.0.1"
        assert SERVER_HOST != "0.0.0.0"

    def test_traffic_endpoint_filtering(self, audit_app_and_client):
        """Verify GET /api/traffic supports limit, offset, protocol, and IP filtering."""
        _, client, db, _ = audit_app_and_client

        records = [
            PacketRecord(timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, protocol="TCP", packet_size=60),
            PacketRecord(timestamp=2.0, src_ip="10.0.0.1", dst_ip="10.0.0.3", src_port=1001, dst_port=53, protocol="UDP", packet_size=70),
            PacketRecord(timestamp=3.0, src_ip="10.0.0.4", dst_ip="10.0.0.2", src_port=None, dst_port=None, protocol="ICMP", packet_size=80),
        ]
        db.insert_traffic_records(records)

        # Filter by protocol
        res_proto = client.get("/api/traffic?protocol=TCP")
        assert res_proto.status_code == 200
        assert len(res_proto.get_json()["records"]) == 1

        # Filter by source IP
        res_src = client.get("/api/traffic?source_ip=10.0.0.1")
        assert res_src.status_code == 200
        assert len(res_src.get_json()["records"]) == 2

        # Filter by destination IP
        res_dst = client.get("/api/traffic?destination_ip=10.0.0.2")
        assert res_dst.status_code == 200
        assert len(res_dst.get_json()["records"]) == 2

    def test_invalid_query_parameters_return_400(self, audit_app_and_client):
        """Verify non-integer or negative limits/offsets return 400 Bad Request."""
        _, client, _, _ = audit_app_and_client
        res_bad_traffic = client.get("/api/traffic?limit=not_a_number")
        assert res_bad_traffic.status_code == 400

        res_bad_offset = client.get("/api/traffic?offset=-5")
        assert res_bad_offset.status_code == 400

        res_bad_alerts = client.get("/api/alerts?limit=xyz")
        assert res_bad_alerts.status_code == 400

    def test_alert_filtering_and_404_handling(self, audit_app_and_client):
        """Verify GET /api/alerts filters and 404 for missing IDs."""
        _, client, db, _ = audit_app_and_client

        alert1 = {"alert_id": "ALT-A1", "timestamp": 10.0, "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "threat_type": "PORT_SCAN", "severity": "HIGH", "risk_score": 70, "status": "NEW", "description": "D1", "evidence": {}}
        alert2 = {"alert_id": "ALT-A2", "timestamp": 11.0, "source_ip": "3.3.3.3", "destination_ip": "4.4.4.4", "threat_type": "SYN_FLOOD", "severity": "CRITICAL", "risk_score": 90, "status": "INVESTIGATING", "description": "D2", "evidence": {}}
        db.insert_alert(alert1)
        db.insert_alert(alert2)

        # Filter by status
        res_status = client.get("/api/alerts?status=INVESTIGATING")
        assert res_status.status_code == 200
        assert len(res_status.get_json()["alerts"]) == 1

        # Missing alert returns 404
        res_404 = client.get("/api/alerts/ALT-DOES-NOT-EXIST")
        assert res_404.status_code == 404


class TestThreadSafetyAndLifecycleAudit:
    """Audit tests for Section 3: Thread Safety, Lifecycle, and Queue Boundaries."""

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_repeated_start_stop_cycles(self, mock_start, tmp_path):
        """Verify monitoring can be started and stopped repeatedly without leakage."""
        db = DatabaseManager(db_path=tmp_path / "cycles.db")
        monitor = MonitorManager(db_manager=db)

        for cycle in range(3):
            assert monitor.is_monitoring is False
            monitor.start_monitoring(interface=None)
            assert monitor.is_monitoring is True
            time.sleep(0.05)
            monitor.stop_monitoring()
            assert monitor.is_monitoring is False
            assert monitor._worker_thread is None

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_queued_packets_drained_on_graceful_shutdown(self, mock_start, tmp_path):
        """Verify worker thread drains remaining queue before shutting down."""
        db = DatabaseManager(db_path=tmp_path / "drain.db")
        monitor = MonitorManager(db_manager=db, batch_size=50, window_seconds=10.0)
        monitor.start_monitoring(interface=None)

        # Enqueue packets that have not reached batch_size
        for i in range(12):
            pkt = PacketRecord(timestamp=100.0 + i, src_ip="192.168.1.5", dst_ip="192.168.1.1", src_port=1000 + i, dst_port=80, protocol="TCP", packet_size=50)
            monitor._enqueue_packet(pkt)

        # Immediately stop monitoring; worker should flush buffer before exit
        monitor.stop_monitoring()

        records = db.get_traffic_records(limit=20)
        assert len(records) == 12

    def test_statistics_preserved_after_stop(self, tmp_path):
        """Verify metrics remain intact and uptime is frozen after stopping."""
        db = DatabaseManager(db_path=tmp_path / "stats_preserve.db")
        monitor = MonitorManager(db_manager=db)

        # Simulate packet arrival
        pkt = PacketRecord(timestamp=10.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=80, protocol="TCP", packet_size=100)
        monitor._update_realtime_counters(pkt)

        monitor.start_time = 100.0
        monitor.stop_time = 125.0
        monitor.is_monitoring = False

        status = monitor.get_status()
        assert status["is_monitoring"] is False
        assert status["total_packets"] == 1
        assert status["total_bytes"] == 100
        assert status["uptime_seconds"] == 25.0
