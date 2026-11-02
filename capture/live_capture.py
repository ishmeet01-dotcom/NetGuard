"""
NetGuard Live Packet Capture Engine
Provides interface enumeration and real-time packet sniffing using Scapy.
"""

from typing import List, Dict, Any, Optional, Callable
import threading
import logging

try:
    from scapy.all import sniff, conf, get_if_list
    from scapy.error import Scapy_Exception
except ImportError:
    sniff = conf = get_if_list = None
    Scapy_Exception = Exception

from preprocessing.packet_parser import parse_scapy_packet, PacketRecord
from preprocessing.traffic_cleaner import TrafficCleaner

logger = logging.getLogger(__name__)


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Enumerate available network interfaces and associated metadata.
    Returns a list of interface dictionaries containing device ID, friendly name,
    description, and assigned IP address.
    """
    if conf is None:
        return []

    interfaces: List[Dict[str, Any]] = []
    default_iface = str(getattr(conf, "iface", ""))

    try:
        # Utilize Scapy's interface provider
        ifaces_dict = getattr(conf, "ifaces", {})
        if ifaces_dict:
            for iface_key, iface_obj in ifaces_dict.items():
                dev_id = str(iface_key)
                friendly_name = str(getattr(iface_obj, "name", dev_id))
                description = str(getattr(iface_obj, "description", ""))
                ip_addr = str(getattr(iface_obj, "ip", ""))
                mac_addr = str(getattr(iface_obj, "mac", ""))

                interfaces.append({
                    "id": dev_id,
                    "name": friendly_name,
                    "description": description,
                    "ip": ip_addr,
                    "mac": mac_addr,
                    "is_default": (dev_id == default_iface or friendly_name == default_iface),
                })
        else:
            # Fallback to standard if_list
            for iface_name in get_if_list():
                interfaces.append({
                    "id": iface_name,
                    "name": iface_name,
                    "description": "",
                    "ip": "",
                    "mac": "",
                    "is_default": (iface_name == default_iface),
                })
    except Exception as exc:
        logger.warning(f"Error enumerating interfaces: {exc}")

    return interfaces


class LiveCaptureEngine:
    """
    Engine for real-time packet capturing on a designated network interface.
    Operates in a background daemon thread with explicit start and stop controls.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ):
        self.interface: Optional[str] = interface
        self.bpf_filter: str = bpf_filter or ""
        self.is_running: bool = False
        self.last_error: Optional[str] = None

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start_capture(self, packet_callback: Callable[[PacketRecord], None]):
        """
        Initiate packet capture in a background thread.
        Passes cleaned PacketRecord instances to the callback function.
        """
        if self.is_running:
            raise RuntimeError("Capture is already active on this engine.")

        if sniff is None:
            raise RuntimeError("Scapy is not installed or sniffing functionality is unavailable.")

        self.last_error = None
        self._stop_event.clear()
        self.is_running = True

        self._thread = threading.Thread(
            target=self._sniff_worker,
            args=(packet_callback,),
            name="NetGuard-ScapySniffer",
            daemon=True,
        )
        self._thread.start()

    def _sniff_worker(self, packet_callback: Callable[[PacketRecord], None]):
        """Background worker executing Scapy's sniff loop."""
        def _packet_handler(raw_pkt):
            try:
                record = parse_scapy_packet(raw_pkt)
                if record is not None:
                    cleaned = TrafficCleaner.clean_record(record)
                    if cleaned is not None:
                        packet_callback(cleaned)
            except Exception:
                pass

        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": _packet_handler,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }

            if self.interface:
                sniff_kwargs["iface"] = self.interface

            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            sniff(**sniff_kwargs)

        except PermissionError:
            self.last_error = (
                "Permission denied: Capturing on Windows requires Administrator privileges "
                "or proper Npcap driver configuration."
            )
            logger.error(self.last_error)
        except (Scapy_Exception, OSError) as exc:
            self.last_error = f"Sniffing error on interface '{self.interface}': {exc}"
            logger.error(self.last_error)
        except Exception as exc:
            self.last_error = f"Unexpected capture failure: {exc}"
            logger.error(self.last_error)
        finally:
            self.is_running = False

    def stop_capture(self, timeout: float = 3.0):
        """Signal the sniff loop to terminate and join the thread."""
        if not self.is_running and (self._thread is None or not self._thread.is_alive()):
            return

        self._stop_event.set()
        self.is_running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            self._thread = None
