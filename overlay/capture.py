from __future__ import annotations

import locale
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
from pathlib import Path


class PacketCapture:
    def __init__(self, pcap_path: str | Path, base_port: int, node_count: int):
        self.pcap_path = Path(pcap_path)
        self.base_port = base_port
        self.last_port = base_port + node_count - 1
        self.dumpcap = self._find_dumpcap()
        self.process: subprocess.Popen | None = None
        self.interface: str | None = None
        self.running = False

    @staticmethod
    def _find_dumpcap() -> str | None:
        executable = shutil.which("dumpcap")
        if executable:
            return executable
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Wireshark" / "dumpcap.exe",
        ]
        return next((str(path) for path in candidates if path.is_file()), None)

    @staticmethod
    def _run(arguments: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(arguments, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"packet capture command failed: {arguments[0]}") from exc
        try:
            stdout = result.stdout.decode("utf-8")
        except UnicodeDecodeError:
            stdout = result.stdout.decode(locale.getpreferredencoding(False), errors="replace")
        try:
            stderr = result.stderr.decode("utf-8")
        except UnicodeDecodeError:
            stderr = result.stderr.decode(locale.getpreferredencoding(False), errors="replace")
        result = subprocess.CompletedProcess(result.args, result.returncode, stdout, stderr)
        if check and result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"packet capture command failed ({result.returncode}): {detail}")
        return result

    def _find_loopback_interface(self) -> str:
        if not self.dumpcap:
            raise RuntimeError(
                "dumpcap was not found. Install Wireshark with Npcap and the Npcap Loopback Adapter "
                "to capture this program's 127.0.0.1 traffic."
            )
        result = self._run([self.dumpcap, "-D"])
        for line in result.stdout.splitlines():
            match = re.match(r"\s*\d+\.\s+(\S+)", line)
            if match and "npf_loopback" in match.group(1).casefold():
                return match.group(1)
        raise RuntimeError(
            "Npcap Loopback Adapter was not listed by dumpcap. Ensure Npcap is installed with "
            "loopback capture support."
        )

    def _filter_expression(self) -> str:
        ports = " or ".join(f"port {port}" for port in range(self.base_port, self.last_port + 1))
        return f"tcp and ({ports})"

    def start(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("automatic loopback pcapng capture currently requires Windows Npcap")
        if self.pcap_path.exists():
            raise FileExistsError(f"capture output already exists: {self.pcap_path}")
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.interface = self._find_loopback_interface()
        arguments = [
            self.dumpcap, "-q", "-i", self.interface, "-f", self._filter_expression(),
            "-w", str(self.pcap_path),
        ]
        try:
            self.process = subprocess.Popen(
                arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except OSError as exc:
            raise RuntimeError(f"could not start dumpcap: {exc}") from exc
        if self.process.poll() is not None:
            _, stderr = self.process.communicate()
            detail = stderr.decode(locale.getpreferredencoding(False), errors="replace").strip()
            self.process = None
            raise RuntimeError(f"dumpcap exited before capture started: {detail}")
        self.running = True

    @staticmethod
    def _packet_count(data: bytes) -> int:
        if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
            raise RuntimeError("capture output is not a valid pcapng file")
        byte_order_magic = data[8:12]
        if byte_order_magic == b"\x4d\x3c\x2b\x1a":
            byte_order = "<"
        elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
            byte_order = ">"
        else:
            raise RuntimeError("pcapng section has an invalid byte-order marker")
        offset = 0
        packet_count = 0
        while offset < len(data):
            if offset + 12 > len(data):
                raise RuntimeError("pcapng contains a truncated block")
            block_type, block_length = struct.unpack_from(f"{byte_order}II", data, offset)
            if block_length < 12 or offset + block_length > len(data):
                raise RuntimeError("pcapng contains an invalid block length")
            trailing_length = struct.unpack_from(f"{byte_order}I", data, offset + block_length - 4)[0]
            if trailing_length != block_length:
                raise RuntimeError("pcapng block length trailer does not match")
            if block_type in {2, 3, 6}:
                packet_count += 1
            offset += block_length
        return packet_count

    @classmethod
    def _verify_capture(cls, data: bytes) -> int:
        packet_count = cls._packet_count(data)
        if packet_count == 0:
            raise RuntimeError("pcapng contains no captured packets")
        for marker in (b"SETI acceptance message", b"failure probe", b"recovered message"):
            if marker in data:
                raise RuntimeError("pcapng contains cleartext application data")
        return packet_count

    def stop(self) -> dict:
        if not self.running or self.process is None:
            raise RuntimeError("packet capture is not running")
        process = self.process
        stopped = False
        verified = False
        try:
            if process.poll() is None:
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                except OSError as exc:
                    raise RuntimeError(f"could not stop dumpcap cleanly: {exc}") from exc
            try:
                _, stderr = process.communicate(timeout=15)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.communicate()
                self.running = False
                self.process = None
                if self.pcap_path.exists():
                    self.pcap_path.unlink()
                raise RuntimeError("dumpcap did not stop after the capture signal") from exc
            stopped = True
            self.running = False
            if process.returncode:
                detail = stderr.decode(locale.getpreferredencoding(False), errors="replace").strip()
                raise RuntimeError(f"dumpcap exited with code {process.returncode}: {detail}")
            capture_bytes = self.pcap_path.read_bytes()
            packet_count = self._verify_capture(capture_bytes)
            verified = True
            return {
                "format": "pcapng",
                "path": self.pcap_path.name,
                "source": "Npcap Loopback Adapter",
                "packet_count": packet_count,
                "contains_application_plaintext": False,
            }
        finally:
            if stopped:
                self.process = None
                if not verified and self.pcap_path.exists():
                    self.pcap_path.unlink()
