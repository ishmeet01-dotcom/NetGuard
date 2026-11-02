"""
NetGuard Background Monitoring Manager
Coordinates live packet capture, bounded queue buffering, multi-threaded
pipeline processing, threat detection, and SQLite persistence.
"""

from typing import Dict, Any, List, Optional
import threading
import queue
import time
import logging

from config import (
    CAPTURE_QUEUE_MAXSIZE,
    PROCESSING_BATCH_SIZE,
    MONITOR_WINDOW_SECONDS,
    WORKER_SHUTDOWN_TIMEOUT_SEC,
    DEFAULT_CAPTURE_FILTER,
)
from preprocessing.packet_parser import PacketRecord
from capture.live_capture import LiveCaptureEngine, get_available_interfaces
from features.feature_extractor import extract_traffic_features
from detection.rule_engine import RuleEngine
from scoring.risk_scorer import RiskScorer
from alerts.alert_manager import AlertManager
from database.db import DatabaseManager

logger = logging.getLogger(__name__)


def _extract_hosts(records: List[PacketRecord]) -> List[Dict[str, Any]]:
    """Helper to extract unique hosts from live packet records."""
    hosts: Dict[str, Dict[str, Any]] = {}
    for r in records:
        if r.src_ip and r.src_ip not in ("0.0.0.0", "255.255.255.255"):
            ip = r.src_ip.strip()
            if ip not in hosts:
                hosts[ip] = {
                    "ip_address": ip,
                    "mac_address": r.src_mac,
                    "first_seen": r.timestamp,
                    "last_seen": r.timestamp,
                    "observation_count": 1,
                }
            else:
                hosts[ip]["last_seen"] = max(hosts[ip]["last_seen"], r.timestamp)
                hosts[ip]["observation_count"] += 1
                if r.src_mac and not hosts[ip]["mac_address"]:
                    hosts[ip]["mac_address"] = r.src_mac
    return list(hosts.values())


class MonitorManager:
    """
    Thread-safe producer-consumer background monitoring orchestrator.
    Decouples Scapy packet sniffing from detection and database operations.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        queue_maxsize: int = CAPTURE_QUEUE_MAXSIZE,
        window_seconds: float = MONITOR_WINDOW_SECONDS,
        batch_size: int = PROCESSING_BATCH_SIZE,
    ):
        self.db = db_manager or DatabaseManager()
        self.queue_maxsize = queue_maxsize
        self.window_seconds = window_seconds
        self.batch_size = batch_size

        self.packet_queue: queue.Queue = queue.Queue(maxsize=self.queue_maxsize)
        self.capture_engine: Optional[LiveCaptureEngine] = None

        # Threading controls
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Detection pipeline components
        self.rule_engine = RuleEngine()
        self.risk_scorer = RiskScorer()
        self.alert_manager = AlertManager()

        # Monitoring state
        self.is_monitoring: bool = False
        self.selected_interface: Optional[str] = None
        self.bpf_filter: str = DEFAULT_CAPTURE_FILTER
        self.start_time: float = 0.0
        self.stop_time: float = 0.0
        self.last_error: Optional[str] = None

        # Real-time metrics
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.dropped_packets: int = 0
        self.detected_threats_count: int = 0
        self.generated_alerts_count: int = 0
        self.protocol_counts: Dict[str, int] = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0
        }
        self.active_sources: set = set()
        self.active_destinations: set = set()
        self.current_pps: float = 0.0
        self.current_bps: float = 0.0

    def start_monitoring(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ) -> bool:
        """
        Start real-time monitoring on the selected interface.
        Enforces single-active-session concurrency protection.
        """
        with self._lock:
            if self.is_monitoring:
                raise RuntimeError("Monitoring session is already active.")

            # Validate interface if provided
            if interface:
                available_ids = [iface["id"] for iface in get_available_interfaces()]
                available_names = [iface["name"] for iface in get_available_interfaces()]
                if interface not in available_ids and interface not in available_names:
                    # Check for partial or case-insensitive match
                    matched = any(
                        interface.lower() in iface["id"].lower() or interface.lower() in iface["name"].lower()
                        for iface in get_available_interfaces()
                    )
                    if not matched and available_ids:
                        raise ValueError(f"Invalid interface '{interface}'. Not found among enumerated interfaces.")

            self.selected_interface = interface
            self.bpf_filter = bpf_filter or ""
            self.last_error = None
            self._stop_event.clear()

            # Clear queue
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break

            # Initialize capture engine
            self.capture_engine = LiveCaptureEngine(
                interface=self.selected_interface,
                bpf_filter=self.bpf_filter,
            )

            # Start worker thread
            self._worker_thread = threading.Thread(
                target=self._processing_worker,
                name="NetGuard-MonitorWorker",
                daemon=True,
            )
            self._worker_thread.start()

            # Start capture engine with callback to queue
            try:
                self.capture_engine.start_capture(self._enqueue_packet)
            except Exception as exc:
                self._stop_event.set()
                self.is_monitoring = False
                self.last_error = str(exc)
                raise

            self.is_monitoring = True
            self.start_time = time.time()
            self.stop_time = 0.0
            logger.info(f"Monitoring started on interface: {self.selected_interface}")
            return True

    def stop_monitoring(self, timeout: float = WORKER_SHUTDOWN_TIMEOUT_SEC) -> bool:
        """Gracefully terminate background capture and worker threads."""
        with self._lock:
            if not self.is_monitoring:
                return True

            self._stop_event.set()
            self.is_monitoring = False
            self.stop_time = time.time()

        # Stop capture engine outside lock
        if self.capture_engine:
            try:
                self.capture_engine.stop_capture(timeout=timeout)
            except Exception as exc:
                logger.warning(f"Error stopping capture engine: {exc}")

        # Wait for worker thread to flush and finish
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            self._worker_thread = None

        logger.info("Monitoring terminated cleanly.")
        return True

    def _enqueue_packet(self, packet: PacketRecord):
        """Producer callback invoked by the capture engine for each parsed packet."""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            with self._lock:
                self.dropped_packets += 1

    def _processing_worker(self):
        """
        Consumer worker that processes packets from the queue in batches and
        applies feature extraction, detection rules, risk scoring, and storage.
        """
        window_buffer: List[PacketRecord] = []
        last_flush_time = time.time()

        while not self._stop_event.is_set() or not self.packet_queue.empty():
            try:
                # Retrieve packet with timeout to allow periodic window flushes
                pkt = self.packet_queue.get(timeout=0.2)
                window_buffer.append(pkt)
                self._update_realtime_counters(pkt)
            except queue.Empty:
                pass

            now = time.time()
            # Process and flush batch if buffer is full or window interval has elapsed
            if window_buffer and (len(window_buffer) >= self.batch_size or (now - last_flush_time) >= self.window_seconds):
                try:
                    self._process_window_batch(window_buffer)
                except Exception as exc:
                    logger.error(f"Error processing window batch: {exc}", exc_info=True)
                    self.last_error = str(exc)

                window_buffer = []
                last_flush_time = now

        # Final drain flush on stop
        if window_buffer:
            try:
                self._process_window_batch(window_buffer)
            except Exception:
                pass

    def _update_realtime_counters(self, pkt: PacketRecord):
        """Increment live real-time statistics counters."""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += int(pkt.packet_size)

            proto = pkt.protocol.upper()
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["OTHER"] += 1

            if pkt.src_ip:
                self.active_sources.add(pkt.src_ip)
            if pkt.dst_ip:
                self.active_destinations.add(pkt.dst_ip)

    def _process_window_batch(self, batch: List[PacketRecord]):
        """
        Run detection pipeline and persist batch records to SQLite.
        """
        if not batch:
            return

        # 1. Feature Extraction (NumPy)
        features = extract_traffic_features(batch)
        summary = features["summary"]

        with self._lock:
            self.current_pps = summary.get("packets_per_second", 0.0)
            self.current_bps = summary.get("bytes_per_second", 0.0)

        # 2. Rule Engine Threat Detection
        raw_detections = self.rule_engine.analyze(batch)

        # 3. Risk Scoring & Alert Management
        if raw_detections:
            scored = self.risk_scorer.score_detections(raw_detections)
            new_alerts = self.alert_manager.process_detections(scored)

            with self._lock:
                self.detected_threats_count += len(raw_detections)
                self.generated_alerts_count += len(new_alerts)

            # 4. Insert Alerts into SQLite
            if new_alerts:
                self.db.insert_alerts(new_alerts)

        # 5. Persist Traffic Records in Batch
        self.db.insert_traffic_records(batch)

        # 6. Save Network Statistics Snapshot
        self.db.save_network_statistics({
            "timestamp": summary.get("last_timestamp") or time.time(),
            "total_packets": summary.get("total_packets", len(batch)),
            "total_bytes": summary.get("total_bytes", 0),
            "packets_per_second": self.current_pps,
            "bytes_per_second": self.current_bps,
            "protocols": features.get("protocols", {}).get("counts", {}),
        })

        # 7. Upsert Known Active Hosts
        hosts = _extract_hosts(batch)
        if hosts:
            self.db.upsert_known_hosts(hosts)

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive live status and statistics."""
        with self._lock:
            uptime = 0.0
            if self.is_monitoring:
                uptime = time.time() - self.start_time
            elif self.stop_time > self.start_time:
                uptime = self.stop_time - self.start_time

            queue_size = self.packet_queue.qsize()

            return {
                "is_monitoring": self.is_monitoring,
                "interface": self.selected_interface,
                "bpf_filter": self.bpf_filter,
                "uptime_seconds": round(uptime, 2),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "current_pps": round(self.current_pps, 2),
                "current_bps": round(self.current_bps, 2),
                "protocol_counts": dict(self.protocol_counts),
                "active_sources_count": len(self.active_sources),
                "active_destinations_count": len(self.active_destinations),
                "detected_threats": self.detected_threats_count,
                "generated_alerts": self.generated_alerts_count,
                "dropped_packets": self.dropped_packets,
                "queue_size": queue_size,
                "queue_capacity": self.queue_maxsize,
                "last_error": self.last_error or (self.capture_engine.last_error if self.capture_engine else None),
            }


# Singleton accessor for application-wide monitoring manager
_GLOBAL_MONITOR_MANAGER: Optional[MonitorManager] = None
_GLOBAL_LOCK = threading.Lock()


def get_monitor_manager(db_manager: Optional[DatabaseManager] = None) -> MonitorManager:
    """Retrieve or initialize the global shared MonitorManager instance."""
    global _GLOBAL_MONITOR_MANAGER
    with _GLOBAL_LOCK:
        if _GLOBAL_MONITOR_MANAGER is None:
            _GLOBAL_MONITOR_MANAGER = MonitorManager(db_manager=db_manager)
        return _GLOBAL_MONITOR_MANAGER
