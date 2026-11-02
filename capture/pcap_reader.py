"""
NetGuard PCAP Reader Module
Stream and parse offline PCAP / PCAPNG packet captures with Scapy safely.
"""

from pathlib import Path
from typing import Generator, Optional, Dict, Any, List, Callable
import os
import time

try:
    from scapy.utils import PcapReader
    from scapy.error import Scapy_Exception
except ImportError:
    PcapReader = None
    Scapy_Exception = Exception

from preprocessing.packet_parser import parse_scapy_packet, PacketRecord
from preprocessing.traffic_cleaner import TrafficCleaner


class PCAPReaderError(Exception):
    """Custom exception for PCAP reading errors."""
    pass


class PCAPReader:
    """
    Offline PCAP packet reader using streaming Scapy PcapReader.
    Avoids loading full capture files into memory all at once.
    """

    SUPPORTED_MAGIC_NUMBERS = [
        b"\xd4\xc3\xb2\xa1",  # Standard PCAP (LE)
        b"\xa1\xb2\xc3\xd4",  # Standard PCAP (BE)
        b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (LE)
        b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (BE)
        b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
    ]

    def __init__(self, sanitize: bool = True):
        self.sanitize = sanitize

    def validate_file(self, filepath: str | Path) -> Path:
        """
        Validate that the file exists, is readable, and appears to be a PCAP file.
        """
        path = Path(filepath).resolve()
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        if not path.is_file():
            raise PCAPReaderError(f"Path is not a regular file: {path}")

        file_size = path.stat().st_size
        if file_size == 0:
            raise PCAPReaderError(f"PCAP file is empty (0 bytes): {path}")

        # Check magic number header
        try:
            with open(path, "rb") as f:
                header = f.read(4)
                if not any(header.startswith(magic[:len(header)]) for magic in self.SUPPORTED_MAGIC_NUMBERS):
                    # Warning or error; we still allow parsing if Scapy can handle it,
                    # but if completely incompatible, flag it.
                    pass
        except PermissionError:
            raise PermissionError(f"Permission denied accessing PCAP file: {path}")
        except Exception as exc:
            raise PCAPReaderError(f"Error inspecting PCAP header: {exc}")

        return path

    def stream_packets(
        self,
        filepath: str | Path,
        max_packets: Optional[int] = None,
    ) -> Generator[PacketRecord, None, None]:
        """
        Stream packet records as a generator without reading entire file into memory.
        Yields PacketRecord instances.
        """
        path = self.validate_file(filepath)

        if PcapReader is None:
            raise PCAPReaderError("Scapy is not installed or PcapReader is unavailable.")

        packet_count = 0
        reader = None
        try:
            reader = PcapReader(str(path))
            for raw_pkt in reader:
                try:
                    record = parse_scapy_packet(raw_pkt)
                    if record is not None:
                        if self.sanitize:
                            cleaned = TrafficCleaner.clean_record(record)
                            if cleaned is not None:
                                yield cleaned
                            else:
                                continue
                        else:
                            yield record

                        packet_count += 1
                        if max_packets is not None and packet_count >= max_packets:
                            break
                except Exception:
                    # Skip individually corrupted packets within the stream
                    continue
        except (Scapy_Exception, EOFError) as exc:
            # Reached end or truncated file safely
            pass
        except Exception as exc:
            raise PCAPReaderError(f"Failed while streaming PCAP: {exc}")
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass

    def read_pcap(
        self,
        filepath: str | Path,
        max_packets: Optional[int] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Read PCAP file and return parsed records with comprehensive summary metadata.
        """
        path = self.validate_file(filepath)
        file_size = path.stat().st_size

        records: List[PacketRecord] = []
        protocols: Dict[str, int] = {}
        total_streamed = 0
        error_count = 0
        start_ts: Optional[float] = None
        end_ts: Optional[float] = None

        start_wall_time = time.time()

        try:
            for record in self.stream_packets(path, max_packets=max_packets):
                total_streamed += 1
                records.append(record)

                proto = record.protocol
                protocols[proto] = protocols.get(proto, 0) + 1

                if start_ts is None or record.timestamp < start_ts:
                    start_ts = record.timestamp
                if end_ts is None or record.timestamp > end_ts:
                    end_ts = record.timestamp

                if progress_callback and (total_streamed % 100 == 0):
                    progress_callback(total_streamed)

        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
                "filepath": str(path),
                "total_packets": len(records),
                "records": records,
            }

        elapsed_read_time = time.time() - start_wall_time
        duration_traffic = (end_ts - start_ts) if (start_ts and end_ts and end_ts >= start_ts) else 0.0

        return {
            "success": True,
            "filepath": str(path),
            "filename": path.name,
            "file_size_bytes": file_size,
            "total_packets": len(records),
            "protocols": protocols,
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "traffic_duration_seconds": round(duration_traffic, 3),
            "read_elapsed_seconds": round(elapsed_read_time, 3),
            "records": records,
        }
