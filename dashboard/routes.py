"""
NetGuard Flask REST API Routes
Implements endpoints for system status, interface enumeration, live capture control,
traffic queries, alert management, and offline PCAP uploads.
"""

from typing import Dict, Any, Optional
import os
import tempfile
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app

from config import (
    MAX_PCAP_UPLOAD_BYTES,
    ALLOWED_PCAP_EXTENSIONS,
    ALERT_CONFIG,
)
from capture.live_capture import get_available_interfaces
from capture.pcap_reader import PCAPReader, PCAPReaderError
from features.feature_extractor import extract_traffic_features
from detection.rule_engine import RuleEngine
from scoring.risk_scorer import RiskScorer
from alerts.alert_manager import AlertManager

api_bp = Blueprint("api", __name__, url_prefix="/api")


def get_db():
    """Retrieve DatabaseManager from current app context."""
    return current_app.config["DB_MANAGER"]


def get_monitor():
    """Retrieve MonitorManager from current app context."""
    return current_app.config["MONITOR_MANAGER"]


# -------------------------------------------------------------
# 1. System Status & Diagnostics
# -------------------------------------------------------------

@api_bp.route("/status", methods=["GET"])
def get_system_status():
    """Return application health, monitoring state, and dashboard counts."""
    db = get_db()
    monitor = get_monitor()

    counts = db.get_dashboard_counts()
    monitor_status = monitor.get_status()

    return jsonify({
        "success": True,
        "status": "online",
        "monitoring": monitor_status,
        "counts": counts,
    }), 200


# -------------------------------------------------------------
# 2. Network Interface Enumeration
# -------------------------------------------------------------

@api_bp.route("/interfaces", methods=["GET"])
def list_interfaces():
    """Enumerate all available network interfaces on the host."""
    interfaces = get_available_interfaces()
    return jsonify({
        "success": True,
        "count": len(interfaces),
        "interfaces": interfaces,
    }), 200


# -------------------------------------------------------------
# 3. Live Monitoring Control
# -------------------------------------------------------------

@api_bp.route("/monitor/start", methods=["POST"])
def start_monitor():
    """Start real-time packet monitoring on a specified interface."""
    monitor = get_monitor()

    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    bpf_filter = data.get("filter", "")

    try:
        monitor.start_monitoring(interface=interface, bpf_filter=bpf_filter)
        return jsonify({
            "success": True,
            "message": "Monitoring initiated successfully.",
            "interface": monitor.selected_interface,
            "filter": monitor.bpf_filter,
        }), 200
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 409
    except Exception as exc:
        return jsonify({"success": False, "error": f"Failed to start monitoring: {exc}"}), 500


@api_bp.route("/monitor/stop", methods=["POST"])
def stop_monitor():
    """Stop real-time packet monitoring."""
    monitor = get_monitor()
    monitor.stop_monitoring()
    return jsonify({
        "success": True,
        "message": "Monitoring stopped successfully.",
    }), 200


@api_bp.route("/monitor/status", methods=["GET"])
def get_monitor_status():
    """Retrieve real-time monitoring counters and throughput metrics."""
    monitor = get_monitor()
    return jsonify({
        "success": True,
        "data": monitor.get_status(),
    }), 200


# -------------------------------------------------------------
# 4. Network Statistics
# -------------------------------------------------------------

@api_bp.route("/statistics", methods=["GET"])
def get_current_statistics():
    """Return live network traffic metrics and protocol breakdown."""
    monitor = get_monitor()
    status = monitor.get_status()

    return jsonify({
        "success": True,
        "total_packets": status["total_packets"],
        "total_bytes": status["total_bytes"],
        "packets_per_second": status["current_pps"],
        "bytes_per_second": status["current_bps"],
        "protocol_counts": status["protocol_counts"],
        "active_sources": status["active_sources_count"],
        "active_destinations": status["active_destinations_count"],
    }), 200


@api_bp.route("/statistics/history", methods=["GET"])
def get_historical_statistics():
    """Retrieve historical traffic metrics snapshots from SQLite."""
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 200)
    history = db.get_recent_statistics(limit=limit)

    return jsonify({
        "success": True,
        "count": len(history),
        "history": history,
    }), 200


# -------------------------------------------------------------
# 5. Traffic Records
# -------------------------------------------------------------

@api_bp.route("/traffic", methods=["GET"])
def get_traffic_records():
    """Query recent traffic packet records from the database with parameterized filters."""
    db = get_db()
    try:
        limit_val = int(request.args.get("limit", 50))
        offset_val = int(request.args.get("offset", 0))
        if limit_val < 1 or offset_val < 0:
            raise ValueError("Limit and offset must be positive integers.")
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid limit or offset parameter."}), 400

    limit = min(limit_val, 500)
    offset = offset_val
    protocol = request.args.get("protocol")
    source_ip = request.args.get("source_ip")
    destination_ip = request.args.get("destination_ip")

    records = db.get_traffic_records(
        limit=limit,
        offset=offset,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )
    return jsonify({
        "success": True,
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "records": records,
    }), 200


# -------------------------------------------------------------
# 6. Security Alerts
# -------------------------------------------------------------

@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """Query security alerts with optional multi-parameter filtering."""
    db = get_db()
    try:
        limit_val = int(request.args.get("limit", 50))
        offset_val = int(request.args.get("offset", 0))
        if limit_val < 1 or offset_val < 0:
            raise ValueError("Limit and offset must be positive integers.")
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid limit or offset parameter."}), 400

    limit = min(limit_val, 500)
    offset = offset_val
    severity = request.args.get("severity")
    threat_type = request.args.get("threat_type")
    status = request.args.get("status")
    source_ip = request.args.get("source_ip")
    destination_ip = request.args.get("destination_ip")

    alerts = db.get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        threat_type=threat_type,
        status=status,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )

    return jsonify({
        "success": True,
        "count": len(alerts),
        "alerts": alerts,
    }), 200


@api_bp.route("/alerts/<alert_id>", methods=["GET"])
def get_alert_detail(alert_id: str):
    """Retrieve full details of a specific security alert by ID."""
    db = get_db()
    alert = db.get_alert_by_id(alert_id)
    if alert is None:
        return jsonify({"success": False, "error": f"Alert '{alert_id}' not found."}), 404

    return jsonify({
        "success": True,
        "alert": alert,
    }), 200


@api_bp.route("/alerts/<alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id: str):
    """Update investigation status of a security alert."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    new_status = str(data.get("status", "")).strip().upper()

    valid_statuses = set(
        ALERT_CONFIG.get("valid_statuses", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
    )

    if new_status not in valid_statuses:
        return jsonify({
            "success": False,
            "error": f"Invalid status '{new_status}'. Allowed: {sorted(list(valid_statuses))}",
        }), 400

    success = db.update_alert_status(alert_id, new_status)
    if not success:
        return jsonify({"success": False, "error": f"Alert '{alert_id}' not found."}), 404

    return jsonify({
        "success": True,
        "message": f"Alert '{alert_id}' status updated to '{new_status}'.",
        "alert_id": alert_id,
        "status": new_status,
    }), 200


# -------------------------------------------------------------
# 7. Known Active Hosts
# -------------------------------------------------------------

@api_bp.route("/hosts", methods=["GET"])
def list_known_hosts():
    """Query known network hosts tracked in SQLite."""
    db = get_db()
    try:
        limit_val = int(request.args.get("limit", 100))
        limit = min(max(1, limit_val), 500)
    except (ValueError, TypeError):
        limit = 100

    search = request.args.get("search")
    hosts = db.get_known_hosts(limit=limit, search=search)

    return jsonify({
        "success": True,
        "count": len(hosts),
        "hosts": hosts,
    }), 200


# -------------------------------------------------------------
# 8. Offline PCAP Upload & Analysis
# -------------------------------------------------------------

@api_bp.route("/analyze/pcap", methods=["POST"])
def analyze_pcap_upload():
    """
    Accept an uploaded PCAP/PCAPNG file, process it safely in a temporary sandbox,
    run the full detection and risk pipeline, persist findings, and return results.
    """
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file field present in request."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename:
        return jsonify({"success": False, "error": "No file selected."}), 400

    # Sanitize client filename against path traversal attacks
    orig_name = os.path.basename(uploaded_file.filename)
    ext = Path(orig_name).suffix.lower()
    if ext not in ALLOWED_PCAP_EXTENSIONS:
        return jsonify({
            "success": False,
            "error": f"Invalid file extension '{ext}'. Allowed: {ALLOWED_PCAP_EXTENSIONS}",
        }), 400

    # Validate file size
    uploaded_file.seek(0, os.SEEK_END)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)

    if file_size > MAX_PCAP_UPLOAD_BYTES:
        max_mb = MAX_PCAP_UPLOAD_BYTES // (1024 * 1024)
        return jsonify({
            "success": False,
            "error": f"File size exceeds maximum upload limit of {max_mb}MB.",
        }), 413

    if file_size == 0:
        return jsonify({"success": False, "error": "Uploaded file is empty (0 bytes)."}), 400

    # Verify actual PCAP magic number bytes signature
    magic_header = uploaded_file.read(4)
    uploaded_file.seek(0)
    valid_magics = PCAPReader.SUPPORTED_MAGIC_NUMBERS
    if not any(magic_header.startswith(m[:len(magic_header)]) for m in valid_magics):
        return jsonify({
            "success": False,
            "error": "Invalid file signature: File content does not match supported PCAP or PCAPNG header magic bytes.",
        }), 400

    # Safe server-side temporary file storage
    temp_fd, temp_path_str = tempfile.mkstemp(suffix=ext, prefix="netguard_upload_")
    os.close(temp_fd)
    temp_path = Path(temp_path_str)

    try:
        uploaded_file.save(str(temp_path))

        # Parse PCAP safely (isolated from live capture)
        reader = PCAPReader()
        read_result = reader.read_pcap(temp_path)

        if not read_result.get("success", False):
            return jsonify({
                "success": False,
                "error": f"Failed to parse capture: {read_result.get('error')}",
            }), 400

        records = read_result.get("records", [])
        features = extract_traffic_features(records)
        summary = features["summary"]

        # Run threat detection & scoring in isolated pipeline
        rule_engine = RuleEngine()
        raw_detections = rule_engine.analyze(records)

        risk_scorer = RiskScorer()
        scored_detections = risk_scorer.score_detections(raw_detections)

        alert_manager = AlertManager()
        generated_alerts = alert_manager.process_detections(scored_detections)

        # Persist to database
        db = get_db()
        traffic_inserted = db.insert_traffic_records(records)
        stat_id = db.save_network_statistics({
            "timestamp": summary["last_timestamp"] or summary["first_timestamp"],
            "total_packets": summary["total_packets"],
            "total_bytes": summary["total_bytes"],
            "packets_per_second": summary["packets_per_second"],
            "bytes_per_second": summary["bytes_per_second"],
            "protocols": features["protocols"]["counts"],
        })

        if generated_alerts:
            db.insert_alerts(generated_alerts)

        return jsonify({
            "success": True,
            "filename": orig_name,
            "total_packets": len(records),
            "traffic_duration_seconds": summary["capture_duration"],
            "protocols": features["protocols"]["counts"],
            "summary": summary,
            "detected_threats_count": len(raw_detections),
            "alerts": generated_alerts,
            "database_records_inserted": traffic_inserted,
        }), 200

    except (PCAPReaderError, FileNotFoundError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"Analysis failed: {exc}"}), 500
    finally:
        # Guarantee cleanup of temporary uploaded file on both success and failure
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
