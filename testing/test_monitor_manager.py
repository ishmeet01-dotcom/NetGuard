"""
NetGuard Unit Tests - Background Monitoring Manager.
Validates multi-threaded queue processing, batch persistence, duplicate worker prevention,
queue overflow safeguards, and real-time counter updates.
"""

import pytest
import time
from unittest.mock import patch

from capture.monitor_manager import MonitorManager
from database.db import DatabaseManager
from preprocessing.packet_parser import PacketRecord


@pytest.fixture
def temp_db(tmp_path) -> DatabaseManager:
    """Create an isolated temporary SQLite database."""
    return DatabaseManager(db_path=tmp_path / "test_monitor.db")


class TestMonitorManager:
    """Tests for MonitorManager producer-consumer mechanics."""

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_start_and_stop_monitoring(self, mock_start, temp_db):
        mgr = MonitorManager(db_manager=temp_db)
        assert mgr.is_monitoring is False

        started = mgr.start_monitoring(interface=None)
        assert started is True
        assert mgr.is_monitoring is True

        # Duplicate start should raise RuntimeError
        with pytest.raises(RuntimeError):
            mgr.start_monitoring(interface=None)

        stopped = mgr.stop_monitoring()
        assert stopped is True
        assert mgr.is_monitoring is False

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_queue_processing_and_batch_persistence(self, mock_start, temp_db):
        # Configure small batch size and short window for rapid test execution
        mgr = MonitorManager(
            db_manager=temp_db,
            batch_size=5,
            window_seconds=0.2,
        )
        mgr.start_monitoring(interface=None)

        # Enqueue packets
        for i in range(10):
            pkt = PacketRecord(
                timestamp=100.0 + i,
                src_ip="192.168.1.50",
                dst_ip="192.168.1.1",
                src_port=5000 + i,
                dst_port=80,
                protocol="TCP",
                packet_size=64,
                tcp_flags="S",
            )
            mgr._enqueue_packet(pkt)

        # Allow worker thread to process and flush
        time.sleep(0.5)
        mgr.stop_monitoring()

        status = mgr.get_status()
        assert status["total_packets"] == 10
        assert status["protocol_counts"]["TCP"] == 10

        # Check records persisted in database
        records = temp_db.get_traffic_records(limit=20)
        assert len(records) == 10

    def test_queue_overflow_handling(self, temp_db):
        # Create manager with tiny queue capacity
        mgr = MonitorManager(db_manager=temp_db, queue_maxsize=2)
        pkt1 = PacketRecord(timestamp=1.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=80, protocol="TCP", packet_size=50)
        pkt2 = PacketRecord(timestamp=2.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=2, dst_port=80, protocol="TCP", packet_size=50)
        pkt3 = PacketRecord(timestamp=3.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=3, dst_port=80, protocol="TCP", packet_size=50)

        mgr._enqueue_packet(pkt1)
        mgr._enqueue_packet(pkt2)
        # 3rd packet exceeds capacity of 2
        mgr._enqueue_packet(pkt3)

        assert mgr.dropped_packets == 1
        assert mgr.packet_queue.qsize() == 2

    @patch("capture.monitor_manager.LiveCaptureEngine.start_capture")
    def test_detection_and_alert_generation_in_stream(self, mock_start, temp_db):
        mgr = MonitorManager(db_manager=temp_db, batch_size=25, window_seconds=0.2)
        mgr.start_monitoring(interface=None)

        # Enqueue a port scan (20 unique ports on 192.168.1.1 within window)
        for i in range(20):
            pkt = PacketRecord(
                timestamp=10.0 + i * 0.01,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=40000 + i,
                dst_port=1000 + i,
                protocol="TCP",
                packet_size=60,
                tcp_flags="S",
            )
            mgr._enqueue_packet(pkt)

        time.sleep(0.5)
        mgr.stop_monitoring()

        status = mgr.get_status()
        assert status["detected_threats"] >= 1
        assert status["generated_alerts"] >= 1

        # Check alert in SQLite
        db_alerts = temp_db.get_alerts()
        assert len(db_alerts) >= 1
        assert db_alerts[0]["threat_type"] == "PORT_SCAN"
