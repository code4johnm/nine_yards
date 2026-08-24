"""Live capture and PCAP replay via dumpcap/tshark, with an in-process PCAP parser fallback.

dumpcap on Kali is typically installed setgid wireshark with cap_net_raw, cap_net_admin.
Live capture still requires membership in group `wireshark` (or root). The dashboard
defaults to localhost and does not start a live tap unless asked.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .parser import TSHARK_FIELDS, parse_frame, parse_tshark_line
from .pcapio import read_pcap

log = logging.getLogger("nids.capture")

PacketCB = Callable[[dict], None]


def tshark_cmd(source: list[str], bpf: str = "") -> list[str]:
    cmd = [
        "tshark",
        "-n",
        "-l",
        "-Q",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for f in TSHARK_FIELDS:
        cmd.extend(["-e", f])
    cmd.extend(source)
    if bpf:
        cmd.extend(["-f", bpf])
    return cmd


class CaptureSession:
    def __init__(
        self,
        on_packet: PacketCB,
        iface: str = "any",
        bpf: str = "",
        store_pcap: bool = False,
        capture_dir: Path | None = None,
        rotate_mb: int = 50,
        rotate_files: int = 8,
    ):
        self.on_packet = on_packet
        self.iface = iface
        self.bpf = bpf
        self.store_pcap = store_pcap
        self.capture_dir = Path(capture_dir) if capture_dir else None
        self.rotate_mb = rotate_mb
        self.rotate_files = rotate_files
        self.proc: subprocess.Popen | None = None
        self.dumpcap: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.packets = 0
        self.drops = 0
        self.last_error: str | None = None
        self.started_at: float | None = None
        self.source = "idle"

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start_live(self) -> None:
        self.stop()
        self._stop.clear()
        if not shutil.which("tshark"):
            self.last_error = "tshark not found"
            raise RuntimeError(self.last_error)
        if self.store_pcap and shutil.which("dumpcap") and self.capture_dir:
            self.capture_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            pcap = self.capture_dir / "live.pcapng"
            dcmd = [
                "dumpcap",
                "-i",
                self.iface,
                "-b",
                f"filesize:{self.rotate_mb * 1024}",
                "-b",
                f"files:{self.rotate_files}",
                "-w",
                str(pcap),
                "-q",
            ]
            if self.bpf:
                dcmd.extend(["-f", self.bpf])
            try:
                self.dumpcap = subprocess.Popen(
                    dcmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except OSError as e:
                log.warning("dumpcap pcap store failed: %s", e)

        cmd = tshark_cmd(["-i", self.iface], self.bpf)
        self._spawn(cmd, source=f"live:{self.iface}")

    def start_pcap(self, path: Path, speed: str = "asfast") -> None:
        self.stop()
        self._stop.clear()
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        if shutil.which("tshark"):
            cmd = tshark_cmd(["-r", str(path)])
            self._spawn(cmd, source=f"pcap:{path.name}")
            return
        self.source = f"pcap-internal:{path.name}"
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._read_pcap_internal, args=(path,), daemon=True)
        self._thread.start()

    def _spawn(self, cmd: list[str], source: str) -> None:
        log.info("starting capture: %s", " ".join(cmd[:12]))
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as e:
            self.last_error = str(e)
            raise
        self.source = source
        self.started_at = time.time()
        self.packets = 0
        self.last_error = None
        self._thread = threading.Thread(target=self._read_tshark, daemon=True)
        self._thread.start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _read_tshark(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in self.proc.stdout:
                if self._stop.is_set():
                    break
                pkt = parse_tshark_line(line, TSHARK_FIELDS)
                if not pkt:
                    continue
                self.packets += 1
                try:
                    self.on_packet(pkt)
                except Exception:
                    log.exception("packet callback failed")
        except Exception as e:
            self.last_error = str(e)
            log.exception("tshark reader failed")
        finally:
            code = self.proc.poll() if self.proc else None
            if code not in (0, None) and not self._stop.is_set():
                err = ""
                if self.proc and self.proc.stderr:
                    try:
                        err = self.proc.stderr.read()[-400:]
                    except Exception:
                        pass
                self.last_error = self.last_error or err or f"tshark exit {code}"

    def _read_pcap_internal(self, path: Path) -> None:
        try:
            for ts, frame in read_pcap(path):
                if self._stop.is_set():
                    break
                pkt = parse_frame(ts, frame)
                if not pkt:
                    continue
                self.packets += 1
                self.on_packet(pkt)
        except Exception as e:
            self.last_error = str(e)
            log.exception("internal pcap reader failed")

    def _drain_stderr(self) -> None:
        if not self.proc or not self.proc.stderr:
            return
        buf = []
        try:
            for line in self.proc.stderr:
                buf.append(line)
                if "dropped" in line.lower():
                    # dumpcap/tshark sometimes print drop counts
                    for tok in line.replace(",", " ").split():
                        if tok.isdigit():
                            self.drops = max(self.drops, int(tok))
                if len(buf) > 40:
                    buf = buf[-20:]
        except Exception:
            pass
        if buf and self.proc and self.proc.poll() not in (0, None):
            self.last_error = "".join(buf)[-500:]

    def stop(self) -> None:
        self._stop.set()
        for proc in (self.proc, self.dumpcap):
            if proc and proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    pass
                try:
                    proc.terminate()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        self.proc = None
        self.dumpcap = None
        self.source = "idle"

    def status(self) -> dict:
        return {
            "running": self.running or (self._thread is not None and self._thread.is_alive() and not self._stop.is_set()),
            "source": self.source,
            "iface": self.iface,
            "packets": self.packets,
            "drops": self.drops,
            "started_at": self.started_at,
            "pid": self.proc.pid if self.proc else None,
            "last_error": self.last_error,
            "store_pcap": self.store_pcap,
        }
