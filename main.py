"""
NetGuard - Network Intrusion Detection System
Main Entry Point & Complete Pipeline Orchestrator
"""

import sys
import argparse
import time
from pathlib import Path
from typing import List, Dict, Any

from config import BASE_DIR, SAMPLES_DIR, DB_PATH
from capture.pcap_reader import PCAPReader, PCAPReaderError
from features.feature_extractor import extract_traffic_features
from detection.rule_engine import RuleEngine
from scoring.risk_scorer import RiskScorer
from alerts.alert_manager import AlertManager
from database.db import DatabaseManager


BANNER = r"""
  _   _      _   _____                     _ 
 | \ | | ___| |_| ____|_   _  __ _ _ __ __| |
 |  \| |/ _ \ __|  _| | | | |/ _` | '__/ _` |
 | |\  |  __/ |_| |___| |_| | (_| | | | (_| |
 |_| \_|\___|\__|_____|\__,_|\__,_|_|  \__,_|
   Network Intrusion Detection System (NIDS)
"""


def extract_hosts_from_records(records) -> List[Dict[str, Any]]:
    """Extract unique active hosts from packet records for the known_hosts table."""
    host_map: Dict[str, Dict[str, Any]] = {}
    for r in records:
        if r.src_ip and r.src_ip not in ("0.0.0.0", "255.255.255.255"):
            ip = r.src_ip.strip()
            if ip not in host_map:
                host_map[ip] = {
                    "ip_address": ip,
                    "mac_address": r.src_mac,
                    "first_seen": r.timestamp,
                    "last_seen": r.timestamp,
                    "observation_count": 1,
                }
            else:
                entry = host_map[ip]
                entry["last_seen"] = max(entry["last_seen"], r.timestamp)
                entry["first_seen"] = min(entry["first_seen"], r.timestamp)
                entry["observation_count"] += 1
                if r.src_mac and not entry["mac_address"]:
                    entry["mac_address"] = r.src_mac
    return list(host_map.values())


def run_pcap_analysis(pcap_path: str, max_packets: int | None = None, persist: bool = True) -> int:
    """Analyze an offline PCAP file and run the full end-to-end detection and persistence pipeline."""
    print(BANNER)
    print(f"[*] Analyzing PCAP: {pcap_path}")
    reader = PCAPReader()

    try:
        result = reader.read_pcap(pcap_path, max_packets=max_packets)
    except (FileNotFoundError, PCAPReaderError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1

    if not result.get("success", False):
        print(f"[!] Failed to parse capture: {result.get('error')}", file=sys.stderr)
        return 1

    print("\n" + "=" * 60)
    print("                 PCAP ANALYSIS SUMMARY           ")
    print("=" * 60)
    print(f"File Name:          {result['filename']}")
    print(f"File Size:          {result['file_size_bytes']} bytes")
    print(f"Total Packets:      {result['total_packets']}")
    print(f"Traffic Duration:   {result['traffic_duration_seconds']}s")
    print(f"Processing Time:    {result['read_elapsed_seconds']}s")
    print("-" * 60)
    print("Protocol Breakdown:")
    for proto, count in result["protocols"].items():
        pct = (count / result["total_packets"]) * 100 if result["total_packets"] else 0
        print(f"  - {proto:<8} : {count:>6} packets ({pct:>5.1f}%)")

    records = result.get("records", [])
    if records:
        # Step 2: Feature Extraction (NumPy)
        features = extract_traffic_features(records)
        summary = features["summary"]
        p_sizes = features["packet_size_percentiles"]
        tcp = features["tcp_flags"]

        print("-" * 60)
        print("Numerical & Vectorized Traffic Statistics (NumPy):")
        print(f"  - Total Volume:     {summary['total_bytes']} bytes")
        print(f"  - Packet Size:      avg={summary['avg_packet_size']}B, std={summary['std_packet_size']}B")
        print(f"  - Size Range:       min={summary['min_packet_size']}B, max={summary['max_packet_size']}B")
        print(f"  - Size Percentiles: p25={p_sizes['p25']}B, p50={p_sizes['p50']}B, p95={p_sizes['p95']}B")
        print(f"  - Transfer Rates:   {summary['packets_per_second']} pps, {summary['bytes_per_second']} bps")
        print(f"  - Unique Entities:  {summary['unique_source_ips']} src IPs, {summary['unique_destination_ips']} dst IPs, {summary['unique_destination_ports']} dst ports")

        if tcp["tcp_packets"] > 0:
            print(f"  - TCP Flags:        SYN={tcp['syn_count']} (only={tcp['syn_only_count']}), ACK={tcp['ack_count']}, FIN={tcp['fin_count']}, RST={tcp['rst_count']}")
            print(f"  - SYN Ratio:        {tcp['syn_to_tcp_ratio'] * 100:.1f}% of TCP packets")

        top_sources = features["source_traffic"]["top_sources"]
        if top_sources:
            print("-" * 60)
            print("Top Source Hosts:")
            for s in top_sources[:5]:
                print(f"  - {s['ip']:<17} : {s['packet_count']:>4} pkts ({s['percentage']:>5.1f}%), {s['total_bytes']:>6} bytes, {s['unique_dst_ports']} target ports")

        top_ports = features["destination_ports"]["top_ports"]
        if top_ports:
            print("-" * 60)
            print("Top Targeted Destination Ports:")
            for p in top_ports[:5]:
                print(f"  - Port {p['port']:<6} : {p['count']:>4} hits")

        # Step 3: Threat Detection Engine
        rule_engine = RuleEngine()
        raw_detections = rule_engine.analyze(records)

        # Step 4: Risk Scoring
        risk_scorer = RiskScorer()
        scored_detections = risk_scorer.score_detections(raw_detections)

        # Step 5: Alert Management & Deduplication
        alert_manager = AlertManager()
        generated_alerts = alert_manager.process_detections(scored_detections)

        print("-" * 60)
        print("Security Threat Detection & Risk Scoring:")
        if generated_alerts:
            print(f"  [!] {len(generated_alerts)} security alert(s) generated:")
            for idx, alt in enumerate(generated_alerts, 1):
                sev_tag = f"[{alt['severity']}]"
                score_tag = f"Score: {alt['risk_score']:.0f}/100"
                print(f"  {idx}. {alt['alert_id']} {alt['threat_type']:<16} {sev_tag:<10} ({score_tag})")
                print(f"     Target: {alt['source_ip']} -> {alt['destination_ip']} (Status: {alt['status']})")
                print(f"     Details: {alt['description']}")
        else:
            print("  [i] No suspicious activity detected under current thresholds.")

        # Step 6: SQLite Persistence
        if persist:
            db = DatabaseManager()
            # Batch traffic insertion
            traffic_inserted = db.insert_traffic_records(records)
            # Save statistics
            stat_id = db.save_network_statistics({
                "timestamp": summary["last_timestamp"] or time.time(),
                "total_packets": summary["total_packets"],
                "total_bytes": summary["total_bytes"],
                "packets_per_second": summary["packets_per_second"],
                "bytes_per_second": summary["bytes_per_second"],
                "protocols": features["protocols"]["counts"],
            })
            # Upsert known hosts
            hosts = extract_hosts_from_records(records)
            hosts_upserted = db.upsert_known_hosts(hosts)

            # Insert alerts with deduplication check
            alerts_inserted = 0
            for alt in generated_alerts:
                # Check if identical alert already exists within deduplication window
                existing = db.get_alerts(
                    threat_type=alt["threat_type"],
                    source_ip=alt["source_ip"],
                    limit=5,
                )
                is_duplicate = any(
                    e["destination_ip"] == alt["destination_ip"]
                    and abs(e["timestamp"] - alt["timestamp"]) <= alert_manager.dedup_window
                    for e in existing
                )
                if not is_duplicate:
                    if db.insert_alert(alt):
                        alerts_inserted += 1

            print("-" * 60)
            print("Database Persistence (SQLite):")
            print(f"  - Database:         {DB_PATH.name}")
            print(f"  - Traffic Records:  {traffic_inserted} inserted")
            print(f"  - Known Hosts:      {hosts_upserted} updated")
            print(f"  - Network Stats:    Snapshot #{stat_id} stored")
            print(f"  - Security Alerts:  {alerts_inserted} new alerts saved ({len(generated_alerts) - alerts_inserted} suppressed duplicates)")

    print("=" * 60)
    return 0


def display_recent_alerts(limit: int = 20) -> int:
    """Query and display recent security alerts from the SQLite database."""
    print(BANNER)
    db = DatabaseManager()
    alerts = db.get_alerts(limit=limit)

    print("\n" + "=" * 65)
    print(f"            RECENT SECURITY ALERTS (LIMIT: {limit})           ")
    print("=" * 65)
    if not alerts:
        print("  [i] No security alerts found in database.")
    else:
        for idx, alt in enumerate(alerts, 1):
            sev_tag = f"[{alt['severity']}]"
            score_tag = f"Score: {alt['risk_score']:.0f}"
            print(f"{idx:>2}. {alt['alert_id']}  {alt['threat_type']:<17} {sev_tag:<10} {score_tag:<11} [{alt['status']}]")
            print(f"    Source: {alt['source_ip']:<15} -> Target: {alt['destination_ip']}")
            print(f"    Timestamp: {alt['timestamp']:.2f}")
            print(f"    Details:   {alt['description']}")
            print("-" * 65)
    print("=" * 65)
    return 0


def display_known_hosts(limit: int = 50) -> int:
    """Display active known network hosts from SQLite database."""
    print(BANNER)
    db = DatabaseManager()
    hosts = db.get_known_hosts(limit=limit)

    print("\n" + "=" * 65)
    print(f"               KNOWN NETWORK HOSTS (LIMIT: {limit})           ")
    print("=" * 65)
    if not hosts:
        print("  [i] No known hosts recorded yet.")
    else:
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Packets':>8} {'Last Seen':>12}")
        print("-" * 65)
        for h in hosts:
            mac = h["mac_address"] or "unknown"
            print(f"{h['ip_address']:<18} {mac:<20} {h['observation_count']:>8} {h['last_seen']:>12.2f}")
    print("=" * 65)
    return 0


def display_database_stats() -> int:
    """Display current database record counts."""
    print(BANNER)
    db = DatabaseManager()
    counts = db.get_dashboard_counts()

    print("\n" + "=" * 45)
    print("         NETGUARD DATABASE SUMMARY           ")
    print("=" * 45)
    print(f"Database Path:         {DB_PATH}")
    print(f"Total Traffic Packets: {counts['total_traffic_packets']:,}")
    print(f"Total Security Alerts: {counts['total_alerts']:,}")
    print(f"Critical Threats:      {counts['critical_threats']:,}")
    print(f"Active Known Hosts:    {counts['active_hosts']:,}")
    print("=" * 45)
    return 0


def display_interfaces() -> int:
    """Enumerate and display available network interfaces on the host."""
    print(BANNER)
    from capture.live_capture import get_available_interfaces
    interfaces = get_available_interfaces()

    print("\n" + "=" * 80)
    print("                     AVAILABLE NETWORK INTERFACES                      ")
    print("=" * 80)
    if not interfaces:
        print("  [!] No network interfaces discovered or Scapy is not initialized.")
    else:
        print(f"{'#':<3} {'Name / Alias':<26} {'IP Address':<16} {'MAC Address':<18} {'Default'}")
        print("-" * 80)
        for idx, iface in enumerate(interfaces, 1):
            is_def = "YES" if iface.get("is_default") else ""
            ip = iface.get("ip") or "None"
            mac = iface.get("mac") or "None"
            name = iface.get("name") or iface.get("id")
            if len(name) > 24:
                name = name[:21] + "..."
            print(f"{idx:<3} {name:<26} {ip:<16} {mac:<18} {is_def}")
    print("=" * 80)
    return 0


def run_live_monitor(interface: Optional[str] = None, bpf_filter: Optional[str] = None) -> int:
    """Run real-time background packet capture and intrusion detection in console."""
    print(BANNER)
    from capture.live_capture import get_available_interfaces
    from capture.monitor_manager import get_monitor_manager

    interfaces = get_available_interfaces()
    selected_iface = interface

    if not selected_iface:
        default_iface = next((i for i in interfaces if i.get("is_default")), None)
        if default_iface:
            selected_iface = default_iface["id"]
            print(f"[*] Auto-selected default interface: {default_iface['name']} ({default_iface['ip']})")
        elif interfaces:
            selected_iface = interfaces[0]["id"]
            print(f"[*] Selected interface: {interfaces[0]['name']}")
        else:
            print("[!] No interfaces available for capture.", file=sys.stderr)
            return 1

    monitor = get_monitor_manager()
    print(f"[*] Starting live intrusion detection engine on interface: {selected_iface}")
    if bpf_filter:
        print(f"[*] Applied BPF filter: '{bpf_filter}'")
    print("[*] Press Ctrl+C at any time to cleanly stop monitoring...\n")

    try:
        monitor.start_monitoring(interface=selected_iface, bpf_filter=bpf_filter)
    except PermissionError:
        print("[!] Permission Denied: Live capturing requires Administrator privileges on Windows.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Failed to initiate monitoring: {exc}", file=sys.stderr)
        return 1

    try:
        header_printed = False
        while monitor.is_monitoring:
            time.sleep(1.5)
            st = monitor.get_status()
            if not header_printed:
                print(f"{'Uptime':<8} {'Packets':<10} {'Volume':<10} {'PPS':<9} {'BPS':<11} {'Alerts':<8} {'Dropped'}")
                print("-" * 70)
                header_printed = True

            vol_str = f"{st['total_bytes'] / 1024:.1f} KB" if st['total_bytes'] < 1048576 else f"{st['total_bytes'] / 1048576:.2f} MB"
            print(f"{st['uptime_seconds']:>6.1f}s  {st['total_packets']:>8}  {vol_str:>9}  {st['current_pps']:>7.1f}  {st['current_bps']:>9.1f}  {st['generated_alerts']:>6}  {st['dropped_packets']:>6}")

    except KeyboardInterrupt:
        print("\n[*] Stopping capture engine gracefully...")
    finally:
        monitor.stop_monitoring()
        final_st = monitor.get_status()
        print("\n" + "=" * 50)
        print("           MONITORING SESSION COMPLETED           ")
        print("=" * 50)
        print(f"Total Duration:     {final_st['uptime_seconds']}s")
        print(f"Total Packets:      {final_st['total_packets']}")
        print(f"Total Bytes:        {final_st['total_bytes']}")
        print(f"Security Alerts:    {final_st['generated_alerts']}")
        print(f"Dropped Packets:    {final_st['dropped_packets']}")
        print("=" * 50)

    return 0


def run_api_server(host: str = "127.0.0.1", port: int = 5000) -> int:
    """Start NetGuard Flask REST API server."""
    print(BANNER)
    from dashboard.app import create_app
    print(f"[*] Starting NetGuard REST API Server on http://{host}:{port}")
    print("[*] Bound exclusively to local interface (127.0.0.1) for defensive prototype security.")
    print("[*] Press Ctrl+C to terminate.")
    app = create_app()
    app.run(host=host, port=port, debug=False)
    return 0


def main() -> int:
    """NetGuard CLI Entry point."""
    parser = argparse.ArgumentParser(
        description="NetGuard - Modular Network Intrusion Detection System"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        help="Path to PCAP file for offline analysis and detection",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Maximum number of packets to process",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Analyze default sample PCAP file in samples/ directory",
    )
    parser.add_argument(
        "--alerts",
        action="store_true",
        help="Display recent security alerts from SQLite database",
    )
    parser.add_argument(
        "--hosts",
        action="store_true",
        help="Display known active network hosts from SQLite database",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display current SQLite database summary and counts",
    )
    parser.add_argument(
        "--interfaces",
        action="store_true",
        help="Enumerate and list available network interfaces",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Start live background intrusion monitoring on selected interface",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Interface ID or alias to monitor with --monitor",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        help="Optional BPF filter expression for live monitoring (e.g. 'tcp port 80')",
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Start the NetGuard Flask REST API server locally (127.0.0.1:5000)",
    )

    args = parser.parse_args()

    if args.interfaces:
        return display_interfaces()

    if args.monitor:
        return run_live_monitor(interface=args.iface, bpf_filter=args.filter)

    if args.server:
        return run_api_server()

    if args.alerts:
        return display_recent_alerts()

    if args.hosts:
        return display_known_hosts()

    if args.stats:
        return display_database_stats()

    if args.sample:
        sample_path = SAMPLES_DIR / "sample_test.pcap"
        return run_pcap_analysis(str(sample_path), max_packets=args.max_packets)

    if args.pcap:
        return run_pcap_analysis(args.pcap, max_packets=args.max_packets)

    print(BANNER)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

