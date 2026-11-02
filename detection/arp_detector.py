"""
NetGuard ARP Anomaly Detector Module
Monitors IP-to-MAC associations over time to detect suspicious mapping changes,
conflicting announcements, and possible ARP spoofing or cache poisoning attempts.
"""

from typing import List, Dict, Any, Optional
from collections import OrderedDict

from config import DETECTION_THRESHOLDS
from preprocessing.packet_parser import PacketRecord


class ARPAnomalyDetector:
    """
    Stateful ARP and MAC-to-IP association detector.
    Flags sudden IP-to-MAC rebindings occurring within the observation window.
    """

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        cfg = thresholds or DETECTION_THRESHOLDS
        self.observation_window_sec: float = float(cfg.get("arp_observation_window_sec", 60.0))
        self.max_history_size: int = int(cfg.get("arp_mapping_history_size", 512))

        # Tracks IP -> {"mac": str, "last_seen": float, "history": List[str]}
        self.ip_mac_table: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def reset_state(self):
        """Reset internal IP-MAC binding table."""
        self.ip_mac_table.clear()

    def detect(self, packets: List[PacketRecord]) -> List[Dict[str, Any]]:
        """
        Scan packet sequence for conflicting IP-to-MAC bindings.
        Works across both ARP packets and Ethernet+IP packet headers.
        """
        if not packets:
            return []

        detections: List[Dict[str, Any]] = []

        # Sort chronologically
        sorted_packets = sorted(packets, key=lambda p: p.timestamp)

        for p in sorted_packets:
            # We observe bindings whenever an IP and a MAC are associated
            ip = p.src_ip
            mac = p.src_mac

            if not ip or not mac or ip in ("0.0.0.0", "255.255.255.255"):
                continue

            # Standardize
            ip = ip.strip()
            mac = mac.strip().lower()

            if ip in self.ip_mac_table:
                entry = self.ip_mac_table[ip]
                prev_mac = entry["mac"]
                prev_seen = entry["last_seen"]
                delta = p.timestamp - prev_seen

                if prev_mac != mac:
                    # MAC has changed for this IP
                    if 0 <= delta <= self.observation_window_sec:
                        # Rapid change detected within observation window
                        mac_history = entry.get("history", [])
                        is_flapping = prev_mac in mac_history

                        confidence = "HIGH" if is_flapping else "MEDIUM"
                        desc = (
                            f"Suspicious ARP mapping change detected: IP {ip} was previously mapped to "
                            f"{prev_mac} and is now claimed by {mac} (delta: {delta:.2f}s). "
                            f"Note: Legitimate changes may occur during DHCP reassignment, VM migration, or router failover."
                        )

                        detections.append({
                            "detected": True,
                            "threat_type": "ARP_ANOMALY",
                            "source_ip": ip,
                            "destination_ip": p.dst_ip or "BROADCAST",
                            "timestamp": round(p.timestamp, 4),
                            "description": desc,
                            "evidence": {
                                "ip_address": ip,
                                "previous_mac": prev_mac,
                                "new_mac": mac,
                                "time_delta_seconds": round(delta, 2),
                                "observation_window_seconds": self.observation_window_sec,
                                "is_flapping": is_flapping,
                                "mac_history": list(set(mac_history + [prev_mac, mac])),
                            },
                            "confidence": confidence,
                        })

                    # Update mapping and history
                    entry["history"].append(prev_mac)
                    entry["mac"] = mac
                    entry["last_seen"] = p.timestamp
                    self.ip_mac_table.move_to_end(ip)
                else:
                    # Same MAC, update timestamp
                    entry["last_seen"] = p.timestamp
                    self.ip_mac_table.move_to_end(ip)
            else:
                # New IP entry
                if len(self.ip_mac_table) >= self.max_history_size:
                    self.ip_mac_table.popitem(last=False)

                self.ip_mac_table[ip] = {
                    "mac": mac,
                    "last_seen": p.timestamp,
                    "history": [],
                }

        return detections
