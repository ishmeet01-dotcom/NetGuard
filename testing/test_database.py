"""
NetGuard Unit Tests - SQLite Database & Persistence Layer.
Validates table creation, batch inserts, parameterization, SQL injection resistance,
UPSERT behavior, transaction rollbacks, and query filtering.
"""

import pytest
import sqlite3
from pathlib import Path

from database.db import DatabaseManager
from preprocessing.packet_parser import PacketRecord


@pytest.fixture
def db_mgr(tmp_path) -> DatabaseManager:
    """Create a DatabaseManager connected to an isolated temporary SQLite database."""
    temp_db = tmp_path / "test_netguard.db"
    return DatabaseManager(db_path=temp_db)


class TestDatabaseManager:
    """Tests for DatabaseManager repository operations."""

    def test_database_initialization(self, db_mgr):
        # Verify all tables exist
        with db_mgr.get_connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            assert {"traffic_records", "security_alerts", "network_statistics", "known_hosts"}.issubset(tables)

    def test_empty_database_queries(self, db_mgr):
        assert db_mgr.get_traffic_records() == []
        assert db_mgr.get_alerts() == []
        assert db_mgr.get_recent_statistics() == []
        assert db_mgr.get_known_hosts() == []
        counts = db_mgr.get_dashboard_counts()
        assert counts["total_traffic_packets"] == 0
        assert counts["total_alerts"] == 0

    def test_batch_traffic_insertion(self, db_mgr):
        records = [
            PacketRecord(
                timestamp=100.0 + i,
                src_ip="192.168.1.10",
                dst_ip="192.168.1.1",
                src_port=1000 + i,
                dst_port=80,
                protocol="TCP",
                packet_size=64,
                tcp_flags="S",
            )
            for i in range(25)
        ]
        inserted = db_mgr.insert_traffic_records(records, batch_size=10)
        assert inserted == 25

        rows = db_mgr.get_traffic_records(limit=50)
        assert len(rows) == 25
        assert rows[0]["protocol"] == "TCP"
        assert rows[0]["packet_size"] == 64

    def test_alert_insertion_and_retrieval(self, db_mgr):
        alert = {
            "alert_id": "ALT-TEST001",
            "timestamp": 123456.78,
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.1",
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "risk_score": 75.0,
            "status": "NEW",
            "description": "Port scan against router",
            "evidence": {"ports_probed": 25, "is_syn_scan": True},
        }
        success = db_mgr.insert_alert(alert)
        assert success is True

        # Fetch and verify JSON deserialization
        fetched = db_mgr.get_alert_by_id("ALT-TEST001")
        assert fetched is not None
        assert fetched["source_ip"] == "10.0.0.50"
        assert fetched["severity"] == "HIGH"
        assert fetched["evidence"]["ports_probed"] == 25
        assert fetched["evidence"]["is_syn_scan"] is True

    def test_alert_status_update_persistence(self, db_mgr):
        alert = {
            "alert_id": "ALT-STATUS1",
            "timestamp": 100.0,
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
            "threat_type": "SYN_FLOOD",
            "severity": "CRITICAL",
            "risk_score": 95.0,
            "status": "NEW",
            "description": "SYN Flood",
            "evidence": {},
        }
        db_mgr.insert_alert(alert)
        updated = db_mgr.update_alert_status("ALT-STATUS1", "INVESTIGATING")
        assert updated is True

        fetched = db_mgr.get_alert_by_id("ALT-STATUS1")
        assert fetched["status"] == "INVESTIGATING"

    def test_known_hosts_upsert(self, db_mgr):
        # Initial insertion
        hosts = [
            {"ip_address": "192.168.1.50", "mac_address": "00:11:22:33:44:55", "first_seen": 10.0, "last_seen": 10.0, "observation_count": 5},
            {"ip_address": "192.168.1.1", "mac_address": "66:77:88:99:aa:bb", "first_seen": 10.0, "last_seen": 10.0, "observation_count": 1},
        ]
        db_mgr.upsert_known_hosts(hosts)
        known = db_mgr.get_known_hosts()
        assert len(known) == 2
        h_50 = next(h for h in known if h["ip_address"] == "192.168.1.50")
        assert h_50["observation_count"] == 5

        # Re-observation of 192.168.1.50 with more packets and later timestamp
        hosts_update = [
            {"ip_address": "192.168.1.50", "mac_address": "00:11:22:33:44:55", "first_seen": 10.0, "last_seen": 25.0, "observation_count": 10},
        ]
        db_mgr.upsert_known_hosts(hosts_update)
        known_after = db_mgr.get_known_hosts()
        assert len(known_after) == 2  # No duplicate host!
        h_50_after = next(h for h in known_after if h["ip_address"] == "192.168.1.50")
        assert h_50_after["observation_count"] == 15  # 5 + 10
        assert h_50_after["last_seen"] == 25.0

    def test_save_and_retrieve_network_statistics(self, db_mgr):
        stats = {
            "timestamp": 200.0,
            "total_packets": 500,
            "total_bytes": 45000,
            "packets_per_second": 50.0,
            "bytes_per_second": 4500.0,
            "protocols": {"TCP": 300, "UDP": 150, "ICMP": 50},
        }
        row_id = db_mgr.save_network_statistics(stats)
        assert row_id > 0

        recent = db_mgr.get_recent_statistics(limit=5)
        assert len(recent) == 1
        assert recent[0]["total_packets"] == 500
        assert recent[0]["protocols"]["TCP"] == 300

    def test_transaction_rollback_on_error(self, db_mgr):
        # Manually trigger an error inside connection context
        with pytest.raises(sqlite3.IntegrityError):
            with db_mgr.get_connection() as conn:
                conn.execute("INSERT INTO security_alerts (alert_id, timestamp, source_ip, destination_ip, threat_type, severity, risk_score, description) VALUES ('ALT-A', 1.0, '1.1.1.1', '2.2.2.2', 'T1', 'LOW', 10, 'desc');")
                # Insert duplicate primary key to cause failure
                conn.execute("INSERT INTO security_alerts (alert_id, timestamp, source_ip, destination_ip, threat_type, severity, risk_score, description) VALUES ('ALT-A', 1.0, '1.1.1.1', '2.2.2.2', 'T1', 'LOW', 10, 'desc');")

        # Entire transaction should have rolled back
        assert db_mgr.get_alerts() == []

    def test_sql_injection_resistance(self, db_mgr):
        # Malicious string input intended to escape or inject SQL
        malicious_ip = "192.168.1.1'; DROP TABLE security_alerts; --"
        alert = {
            "alert_id": "ALT-INJECT1",
            "timestamp": 100.0,
            "source_ip": malicious_ip,
            "destination_ip": "10.0.0.1",
            "threat_type": "PORT_SCAN",
            "severity": "HIGH",
            "risk_score": 70.0,
            "description": "Safe parameter test",
            "evidence": {},
        }
        db_mgr.insert_alert(alert)

        # Table should still exist intact!
        alerts = db_mgr.get_alerts(source_ip=malicious_ip)
        assert len(alerts) == 1
        assert alerts[0]["source_ip"] == malicious_ip

        # Verify table was NOT dropped
        with db_mgr.get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM security_alerts;")
            assert cursor.fetchone()[0] == 1
