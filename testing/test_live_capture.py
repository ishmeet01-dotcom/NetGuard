"""
NetGuard Unit Tests - Live Capture Engine.
Validates interface enumeration, capture thread management, graceful shutdown,
and error handling with mock packet providers.
"""

import pytest
import time
from unittest.mock import patch, MagicMock

from capture.live_capture import LiveCaptureEngine, get_available_interfaces
from preprocessing.packet_parser import PacketRecord


class TestLiveCaptureEngine:
    """Tests for LiveCaptureEngine and interface enumeration."""

    def test_get_available_interfaces_returns_list(self):
        interfaces = get_available_interfaces()
        assert isinstance(interfaces, list)
        if interfaces:
            first = interfaces[0]
            assert "id" in first
            assert "name" in first
            assert "description" in first
            assert "ip" in first

    def test_engine_initialization(self):
        engine = LiveCaptureEngine(interface="eth0", bpf_filter="tcp port 80")
        assert engine.interface == "eth0"
        assert engine.bpf_filter == "tcp port 80"
        assert engine.is_running is False

    @patch("capture.live_capture.sniff")
    def test_start_and_stop_capture_cleanly(self, mock_sniff):
        # Setup mock sniff that sleeps briefly to simulate sniffing
        def fake_sniff(**kwargs):
            stop_filter = kwargs.get("stop_filter")
            while not (stop_filter and stop_filter(None)):
                time.sleep(0.02)

        mock_sniff.side_effect = fake_sniff

        engine = LiveCaptureEngine(interface="mock_iface")
        callback = MagicMock()

        engine.start_capture(callback)
        assert engine.is_running is True

        # Duplicate start raises RuntimeError
        with pytest.raises(RuntimeError):
            engine.start_capture(callback)

        engine.stop_capture(timeout=1.0)
        assert engine.is_running is False

    @patch("capture.live_capture.sniff")
    def test_permission_error_handling(self, mock_sniff):
        mock_sniff.side_effect = PermissionError("Administrator privileges required")

        engine = LiveCaptureEngine(interface="mock_iface")
        engine.start_capture(lambda _: None)

        # Allow worker thread to catch error
        time.sleep(0.1)
        assert engine.is_running is False
        assert engine.last_error is not None
        assert "Permission denied" in engine.last_error

    @patch("capture.live_capture.sniff")
    def test_scapy_exception_handling(self, mock_sniff):
        mock_sniff.side_effect = OSError("Interface unavailable")

        engine = LiveCaptureEngine(interface="nonexistent_iface")
        engine.start_capture(lambda _: None)

        time.sleep(0.1)
        assert engine.is_running is False
        assert "Sniffing error" in engine.last_error
