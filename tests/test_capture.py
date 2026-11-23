import signal
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from overlay.capture import PacketCapture


def pcapng_with_packet(packet_data: bytes = b"\x00" * 60) -> bytes:
    section = (
        struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    padding = b"\x00" * ((-len(packet_data)) % 4)
    block_length = 32 + len(packet_data) + len(padding)
    packet = (
        struct.pack("<IIIIIII", 6, block_length, 0, 0, 0, len(packet_data), len(packet_data))
        + packet_data + padding + struct.pack("<I", block_length)
    )
    return section + interface + packet


def empty_pcapng() -> bytes:
    section = (
        struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    return section + interface


class FakeCaptureProcess:
    returncode = 0

    def __init__(self):
        self.signals = []

    def poll(self):
        return None

    def send_signal(self, value):
        self.signals.append(value)

    def communicate(self, timeout=None):
        return b"", b""


class PacketCaptureTests(unittest.TestCase):
    def test_dumpcap_output_decodes_utf8(self):
        response = subprocess.CompletedProcess(
            ["dumpcap", "-D"], 0, "Интерфейс".encode("utf-8"), b"",
        )
        with patch("overlay.capture.subprocess.run", return_value=response):
            result = PacketCapture._run(["dumpcap", "-D"])
        self.assertEqual(result.stdout, "Интерфейс")

    def test_selects_npcap_loopback_interface(self):
        capture = PacketCapture("capture.pcapng", 19000, 12)
        capture.dumpcap = "dumpcap"
        response = subprocess.CompletedProcess(
            ["dumpcap", "-D"], 0,
            "1. \\Device\\NPF_{123} (Ethernet)\n"
            "2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n",
            "",
        )
        with patch.object(capture, "_run", return_value=response):
            self.assertEqual(capture._find_loopback_interface(), r"\Device\NPF_Loopback")

    def test_requires_npcap_loopback_interface(self):
        capture = PacketCapture("capture.pcapng", 19000, 12)
        capture.dumpcap = "dumpcap"
        response = subprocess.CompletedProcess(
            ["dumpcap", "-D"], 0, "1. \\Device\\NPF_{123} (Ethernet)", "",
        )
        with patch.object(capture, "_run", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "Npcap Loopback Adapter"):
                capture._find_loopback_interface()

    def test_filter_expression_includes_each_overlay_port(self):
        capture = PacketCapture("capture.pcapng", 19000, 12)
        self.assertEqual(
            capture._filter_expression(),
            "tcp and (" + " or ".join(f"port {port}" for port in range(19000, 19012)) + ")",
        )

    def test_start_launches_dumpcap_on_loopback(self):
        capture = PacketCapture("capture.pcapng", 19000, 12)
        capture.dumpcap = "dumpcap"
        process = FakeCaptureProcess()
        with tempfile.TemporaryDirectory() as temp_dir:
            capture.pcap_path = Path(temp_dir) / "capture.pcapng"
            with patch("overlay.capture.sys.platform", "win32"), \
                    patch.object(capture, "_find_loopback_interface",
                                 return_value=r"\Device\NPF_Loopback"), \
                    patch("overlay.capture.subprocess.Popen", return_value=process) as popen:
                capture.start()

        args = popen.call_args.args[0]
        self.assertEqual(args[:4], ["dumpcap", "-q", "-i", r"\Device\NPF_Loopback"])
        self.assertIn("-f", args)
        self.assertEqual(args[-2], "-w")
        self.assertTrue(capture.running)

    def test_stop_sends_break_and_verifies_pcapng(self):
        capture = PacketCapture("capture.pcapng", 19000, 12)
        process = FakeCaptureProcess()
        capture.process = process
        capture.running = True
        with tempfile.TemporaryDirectory() as temp_dir:
            capture.pcap_path = Path(temp_dir) / "capture.pcapng"
            capture.pcap_path.write_bytes(pcapng_with_packet())
            result = capture.stop()

        self.assertEqual(process.signals, [signal.CTRL_BREAK_EVENT])
        self.assertEqual(result["format"], "pcapng")
        self.assertEqual(result["packet_count"], 1)
        self.assertFalse(result["contains_application_plaintext"])
        self.assertFalse(capture.running)

    def test_rejects_empty_or_plaintext_capture(self):
        with self.assertRaisesRegex(RuntimeError, "no captured packets"):
            PacketCapture._verify_capture(empty_pcapng())
        with self.assertRaisesRegex(RuntimeError, "cleartext application data"):
            PacketCapture._verify_capture(pcapng_with_packet(b"SETI acceptance message"))

    def test_rejects_invalid_and_malformed_pcapng(self):
        with self.assertRaises(RuntimeError):
            PacketCapture._packet_count(b"not a capture")
        malformed = bytearray(pcapng_with_packet())
        struct.pack_into("<I", malformed, 4, 512)
        with self.assertRaises(RuntimeError):
            PacketCapture._packet_count(bytes(malformed))


if __name__ == "__main__":
    unittest.main()
