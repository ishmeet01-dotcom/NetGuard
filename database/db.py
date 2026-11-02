"""
NetGuard Database Repository & Persistence Layer
Provides secure, parameterized SQLite operations for traffic records,
security alerts, network analytics, and known host tracking.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from contextlib import contextmanager
import sqlite3
import json

from config import DB_PATH, DB_BATCH_SIZE
from preprocessing.packet_parser import PacketRecord


class DatabaseManager:
    """
    Manages SQLite database connections, schema migrations, and parameterized CRUD operations.
    Thread-safe through connection-per-context pattern.
    """

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path or DB_PATH).resolve()
        self.schema_path = Path(__file__).resolve().parent / "schema.sql"
        self._initialize_database()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an isolated, auto-committing database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_database(self):
        """Execute schema.sql to ensure all required tables and indexes exist."""
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Database schema file not found at {self.schema_path}")

        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.get_connection() as conn:
            conn.executescript(schema_sql)

    # ---------------------------------------------------------
    # Traffic Records Operations
    # ---------------------------------------------------------

    def insert_traffic_records(
        self, records: List[PacketRecord], batch_size: int = DB_BATCH_SIZE
    ) -> int:
        """Batch insert PacketRecord objects using parameterized transactions."""
        if not records:
            return 0

        query = """
            INSERT INTO traffic_records (
                timestamp, source_ip, destination_ip, source_port, destination_port,
                protocol, packet_size, tcp_flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """

        total_inserted = 0
        with self.get_connection() as conn:
            for i in range(0, len(records), batch_size):
                batch = records[i : i + batch_size]
                params = [
                    (
                        float(r.timestamp),
                        r.src_ip,
                        r.dst_ip,
                        r.src_port,
                        r.dst_port,
                        r.protocol,
                        int(r.packet_size),
                        r.tcp_flags,
                    )
                    for r in batch
                ]
                conn.executemany(query, params)
                total_inserted += len(batch)

        return total_inserted

    def get_traffic_records(
        self,
        limit: int = 100,
        offset: int = 0,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent traffic records with optional parameterized filters."""
        conditions = []
        params: List[Any] = []

        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol.strip().upper())

        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip.strip())

        if destination_ip:
            conditions.append("destination_ip = ?")
            params.append(destination_ip.strip())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT id, timestamp, source_ip, destination_ip, source_port, destination_port,
                   protocol, packet_size, tcp_flags
            FROM traffic_records
            {where_clause}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    # ---------------------------------------------------------
    # Security Alerts Operations
    # ---------------------------------------------------------

    def insert_alert(self, alert: Dict[str, Any]) -> bool:
        """Insert a single security alert with parameterized query."""
        query = """
            INSERT OR IGNORE INTO security_alerts (
                alert_id, timestamp, source_ip, destination_ip, threat_type,
                severity, risk_score, status, description, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        evidence_json = json.dumps(alert.get("evidence", {}))
        with self.get_connection() as conn:
            cursor = conn.execute(
                query,
                (
                    alert["alert_id"],
                    float(alert["timestamp"]),
                    alert["source_ip"],
                    alert["destination_ip"],
                    alert["threat_type"],
                    alert["severity"],
                    float(alert["risk_score"]),
                    alert.get("status", "NEW"),
                    alert["description"],
                    evidence_json,
                ),
            )
            return cursor.rowcount > 0

    def insert_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        """Batch insert security alerts."""
        if not alerts:
            return 0

        query = """
            INSERT OR IGNORE INTO security_alerts (
                alert_id, timestamp, source_ip, destination_ip, threat_type,
                severity, risk_score, status, description, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = [
            (
                a["alert_id"],
                float(a["timestamp"]),
                a["source_ip"],
                a["destination_ip"],
                a["threat_type"],
                a["severity"],
                float(a["risk_score"]),
                a.get("status", "NEW"),
                a["description"],
                json.dumps(a.get("evidence", {})),
            )
            for a in alerts
        ]
        with self.get_connection() as conn:
            cursor = conn.executemany(query, params)
            return cursor.rowcount

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve security alerts filtered by optional fields using parameterized queries."""
        conditions = []
        params: List[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.strip().upper())

        if threat_type:
            conditions.append("threat_type = ?")
            params.append(threat_type.strip().upper())

        if status:
            conditions.append("status = ?")
            params.append(status.strip().upper())

        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip.strip())

        if destination_ip:
            conditions.append("destination_ip = ?")
            params.append(destination_ip.strip())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT alert_id, timestamp, source_ip, destination_ip, threat_type,
                   severity, risk_score, status, description, evidence_json
            FROM security_alerts
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([limit, offset])

        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                try:
                    item["evidence"] = json.loads(item.pop("evidence_json", "{}"))
                except Exception:
                    item["evidence"] = {}
                results.append(item)
            return results

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific alert by ID."""
        query = """
            SELECT alert_id, timestamp, source_ip, destination_ip, threat_type,
                   severity, risk_score, status, description, evidence_json
            FROM security_alerts
            WHERE alert_id = ?;
        """
        with self.get_connection() as conn:
            cursor = conn.execute(query, (alert_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            item = dict(row)
            try:
                item["evidence"] = json.loads(item.pop("evidence_json", "{}"))
            except Exception:
                item["evidence"] = {}
            return item

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """Update an alert's investigation status."""
        query = """
            UPDATE security_alerts
            SET status = ?
            WHERE alert_id = ?;
        """
        with self.get_connection() as conn:
            cursor = conn.execute(query, (new_status.strip().upper(), alert_id))
            return cursor.rowcount > 0

    # ---------------------------------------------------------
    # Network Statistics Operations
    # ---------------------------------------------------------

    def save_network_statistics(self, stats: Dict[str, Any]) -> int:
        """Persist network analytics summary into network_statistics table."""
        query = """
            INSERT INTO network_statistics (
                timestamp, total_packets, total_bytes, packets_per_second,
                bytes_per_second, protocol_distribution_json
            ) VALUES (?, ?, ?, ?, ?, ?);
        """
        proto_json = json.dumps(stats.get("protocols", {}))
        with self.get_connection() as conn:
            cursor = conn.execute(
                query,
                (
                    float(stats.get("timestamp", 0.0)),
                    int(stats.get("total_packets", 0)),
                    int(stats.get("total_bytes", 0)),
                    float(stats.get("packets_per_second", 0.0)),
                    float(stats.get("bytes_per_second", 0.0)),
                    proto_json,
                ),
            )
            return cursor.lastrowid or 0

    def get_recent_statistics(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent network statistics snapshots."""
        query = """
            SELECT id, timestamp, total_packets, total_bytes, packets_per_second,
                   bytes_per_second, protocol_distribution_json
            FROM network_statistics
            ORDER BY timestamp DESC, id DESC
            LIMIT ?;
        """
        with self.get_connection() as conn:
            cursor = conn.execute(query, (limit,))
            results = []
            for row in cursor.fetchall():
                item = dict(row)
                try:
                    item["protocols"] = json.loads(item.pop("protocol_distribution_json", "{}"))
                except Exception:
                    item["protocols"] = {}
                results.append(item)
            return results

    # ---------------------------------------------------------
    # Known Hosts Operations
    # ---------------------------------------------------------

    def upsert_known_hosts(self, hosts: List[Dict[str, Any]]) -> int:
        """
        Insert or update active network hosts using SQLite UPSERT.
        Increments observation counts and updates last seen timestamps.
        """
        if not hosts:
            return 0

        query = """
            INSERT INTO known_hosts (
                ip_address, mac_address, first_seen, last_seen, observation_count
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address = COALESCE(excluded.mac_address, known_hosts.mac_address),
                last_seen = MAX(known_hosts.last_seen, excluded.last_seen),
                observation_count = known_hosts.observation_count + excluded.observation_count;
        """
        params = [
            (
                h["ip_address"].strip(),
                h.get("mac_address"),
                float(h.get("first_seen", 0.0)),
                float(h.get("last_seen", 0.0)),
                int(h.get("observation_count", 1)),
            )
            for h in hosts
            if h.get("ip_address")
        ]

        with self.get_connection() as conn:
            cursor = conn.executemany(query, params)
            return cursor.rowcount

    def get_known_hosts(self, limit: int = 100, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve known network hosts ordered by activity with optional IP/MAC search."""
        conditions = []
        params: List[Any] = []
        if search:
            conditions.append("(ip_address LIKE ? OR mac_address LIKE ?)")
            term = f"%{search.strip()}%"
            params.extend([term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT id, ip_address, mac_address, first_seen, last_seen, observation_count
            FROM known_hosts
            {where_clause}
            ORDER BY observation_count DESC, last_seen DESC
            LIMIT ?;
        """
        params.append(limit)
        with self.get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    # ---------------------------------------------------------
    # Aggregation & Overview Counts
    # ---------------------------------------------------------

    def get_dashboard_counts(self) -> Dict[str, int]:
        """Retrieve high-level metric counts for dashboard cards."""
        with self.get_connection() as conn:
            traffic_count = conn.execute("SELECT COUNT(*) FROM traffic_records;").fetchone()[0]
            alerts_count = conn.execute("SELECT COUNT(*) FROM security_alerts;").fetchone()[0]
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM security_alerts WHERE severity = 'CRITICAL';"
            ).fetchone()[0]
            hosts_count = conn.execute("SELECT COUNT(*) FROM known_hosts;").fetchone()[0]

            return {
                "total_traffic_packets": int(traffic_count),
                "total_alerts": int(alerts_count),
                "critical_threats": int(critical_count),
                "active_hosts": int(hosts_count),
            }
