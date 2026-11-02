"""
NetGuard Alert Manager Module
Generates standardized security alerts, manages investigation statuses,
deduplicates security events, and provides multi-field alert filtering.
"""

from typing import List, Dict, Any, Optional
import uuid
import time

from config import ALERT_CONFIG


class AlertManager:
    """
    Manages security alert lifecycles: generation, status tracking,
    deduplication, and in-memory history.
    """

    VALID_STATUSES = set(
        ALERT_CONFIG.get("valid_statuses", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
    )

    def __init__(self, dedup_window: Optional[float] = None):
        self.dedup_window: float = float(
            dedup_window or ALERT_CONFIG.get("deduplication_window_sec", 10.0)
        )
        self.alerts: List[Dict[str, Any]] = []

    def clear(self):
        """Clear in-memory alert history."""
        self.alerts.clear()

    @staticmethod
    def generate_alert_id() -> str:
        """Generate a compact, unique alert identifier."""
        return f"ALT-{uuid.uuid4().hex[:10].upper()}"

    def create_alert_from_detection(self, scored_detection: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create and record a new Security Alert from a scored detection record.
        Applies duplicate suppression against recent alerts in memory.
        """
        threat_type = scored_detection.get("threat_type", "UNKNOWN")
        src_ip = scored_detection.get("source_ip", "")
        dst_ip = scored_detection.get("destination_ip", "")
        ts = float(scored_detection.get("timestamp", time.time()))

        # Check for duplicate within deduplication window
        for existing in self.alerts:
            if (
                existing["threat_type"] == threat_type
                and existing["source_ip"] == src_ip
                and existing["destination_ip"] == dst_ip
                and abs(ts - existing["timestamp"]) <= self.dedup_window
            ):
                # Duplicate event found within window; suppress creating another alert
                return None

        alert_id = self.generate_alert_id()
        alert: Dict[str, Any] = {
            "alert_id": alert_id,
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "threat_type": threat_type,
            "severity": scored_detection.get("severity", "LOW"),
            "risk_score": float(scored_detection.get("risk_score", 0.0)),
            "status": "NEW",
            "description": scored_detection.get("description", ""),
            "evidence": scored_detection.get("evidence", {}),
        }

        self.alerts.append(alert)
        return alert

    def process_detections(self, scored_detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a list of scored detections and return newly generated alerts."""
        new_alerts = []
        for d in scored_detections:
            alert = self.create_alert_from_detection(d)
            if alert is not None:
                new_alerts.append(alert)
        return new_alerts

    def update_status(self, alert_id: str, new_status: str) -> bool:
        """
        Update the investigation status of an existing alert.
        Validates status against allowed enum values.
        """
        status_clean = new_status.strip().upper()
        if status_clean not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid alert status '{new_status}'. Allowed: {sorted(list(self.VALID_STATUSES))}"
            )

        for alert in self.alerts:
            if alert["alert_id"] == alert_id:
                alert["status"] = status_clean
                return True
        return False

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific alert by its ID."""
        for alert in self.alerts:
            if alert["alert_id"] == alert_id:
                return dict(alert)
        return None

    def filter_alerts(
        self,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Filter alert collection by various security criteria."""
        results = self.alerts

        if severity:
            s_clean = severity.strip().upper()
            results = [a for a in results if a.get("severity") == s_clean]

        if threat_type:
            t_clean = threat_type.strip().upper()
            results = [a for a in results if a.get("threat_type") == t_clean]

        if status:
            st_clean = status.strip().upper()
            results = [a for a in results if a.get("status") == st_clean]

        if source_ip:
            results = [a for a in results if a.get("source_ip") == source_ip.strip()]

        if destination_ip:
            results = [a for a in results if a.get("destination_ip") == destination_ip.strip()]

        return [dict(a) for a in results]
