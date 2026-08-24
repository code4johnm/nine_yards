"""Optional tailers for Suricata EVE JSON, Zeek TSV logs, and syslog.

These are ingest-only. If the files are absent the dashboard stays on the
built-in statistical detector + DEMO set.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable

log = logging.getLogger("nids.sensors")

AlertCB = Callable[[dict], None]
FlowCB = Callable[[dict], None]


def _sev_from_suricata(n: int | None, fallback: str = "medium") -> str:
    # Suricata: 1=high, 2=medium, 3=low
    return {1: "high", 2: "medium", 3: "low"}.get(int(n or 0), fallback)


class FileTailer:
    def __init__(self, path: Path, on_line: Callable[[str], None], interval: float = 0.5):
        self.path = Path(path)
        self.on_line = on_line
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.offset = 0
        self.inode: int | None = None
        self.lines = 0
        self.last_error: str | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if not self.path.exists():
                    time.sleep(self.interval * 4)
                    continue
                st = self.path.stat()
                if self.inode is None:
                    # start at end for live files, start at 0 if small sample
                    self.inode = st.st_ino
                    self.offset = 0 if st.st_size < 5_000_000 else st.st_size
                if st.st_ino != self.inode or st.st_size < self.offset:
                    self.inode = st.st_ino
                    self.offset = 0
                with self.path.open("r", errors="replace") as f:
                    f.seek(self.offset)
                    while not self._stop.is_set():
                        line = f.readline()
                        if not line:
                            self.offset = f.tell()
                            break
                        self.lines += 1
                        try:
                            self.on_line(line)
                        except Exception:
                            log.exception("tail callback failed for %s", self.path)
                    self.offset = f.tell()
            except Exception as e:
                self.last_error = str(e)
                log.warning("tail %s: %s", self.path, e)
            time.sleep(self.interval)


class SensorHub:
    def __init__(self, on_alert: AlertCB, on_flow: FlowCB | None = None):
        self.on_alert = on_alert
        self.on_flow = on_flow
        self.tailers: list[FileTailer] = []

    def start(self, eve_path: str = "", zeek_dir: str = "", syslog_path: str = "") -> list[str]:
        started = []
        if eve_path:
            p = Path(eve_path)
            t = FileTailer(p, self._eve_line)
            t.start()
            self.tailers.append(t)
            started.append(f"suricata-eve:{p}")
        if zeek_dir:
            d = Path(zeek_dir)
            for name, handler in (
                ("conn.log", self._zeek_conn),
                ("dns.log", self._zeek_dns),
                ("http.log", self._zeek_http),
                ("ssl.log", self._zeek_ssl),
                ("weird.log", self._zeek_weird),
                ("notice.log", self._zeek_notice),
            ):
                p = d / name
                t = FileTailer(p, handler)
                t.start()
                self.tailers.append(t)
                started.append(f"zeek:{name}")
        if syslog_path:
            p = Path(syslog_path)
            t = FileTailer(p, self._syslog_line)
            t.start()
            self.tailers.append(t)
            started.append(f"syslog:{p}")
        return started

    def stop(self) -> None:
        for t in self.tailers:
            t.stop()
        self.tailers.clear()

    def _eve_line(self, line: str) -> None:
        line = line.strip()
        if not line or not line.startswith("{"):
            return
        rec = json.loads(line)
        et = rec.get("event_type")
        if et != "alert":
            return
        alert = rec.get("alert") or {}
        sev = _sev_from_suricata(alert.get("severity"))
        if rec.get("demo"):
            source = "suricata-demo"
            is_demo = True
        else:
            source = "suricata"
            is_demo = False
        self.on_alert(
            {
                "ts": _parse_iso(rec.get("timestamp")),
                "severity": sev,
                "signature": alert.get("signature") or "suricata-alert",
                "sid": str(alert.get("signature_id") or ""),
                "category": alert.get("category") or "unclassified",
                "src_ip": rec.get("src_ip"),
                "dst_ip": rec.get("dest_ip"),
                "src_port": rec.get("src_port"),
                "dst_port": rec.get("dest_port"),
                "proto": rec.get("proto"),
                "source": source,
                "is_demo": is_demo,
                "extra": {"gid": alert.get("gid"), "action": alert.get("action")},
            }
        )

    def _zeek_headers(self, path_hint: str, line: str, cache: dict) -> list[str] | None:
        if line.startswith("#fields"):
            cache["fields"] = line.strip().split("\t")[1:]
            return None
        if line.startswith("#"):
            return None
        fields = cache.get("fields")
        if not fields:
            return None
        return fields

    def _split_zeek(self, line: str, cache: dict) -> dict | None:
        if line.startswith("#fields"):
            cache["fields"] = line.strip().split("\t")[1:]
            return None
        if line.startswith("#") or not line.strip():
            return None
        fields = cache.get("fields")
        if not fields:
            return None
        parts = line.rstrip("\n").split("\t")
        rec = {}
        for i, k in enumerate(fields):
            rec[k] = parts[i] if i < len(parts) else None
        return rec

    def __init_caches(self) -> None:
        if not hasattr(self, "_zcache"):
            self._zcache = {k: {} for k in ("conn", "dns", "http", "ssl", "weird", "notice")}

    def _zeek_conn(self, line: str) -> None:
        self.__init_caches()
        rec = self._split_zeek(line, self._zcache["conn"])
        if not rec or not self.on_flow:
            return
        try:
            ts = float(rec.get("ts") or 0)
            duration = float(rec.get("duration") or 0) if rec.get("duration") not in ("-", None, "") else 0
        except ValueError:
            return
        self.on_flow(
            {
                "src_ip": rec.get("id.orig_h"),
                "dst_ip": rec.get("id.resp_h"),
                "src_port": _int(rec.get("id.orig_p")),
                "dst_port": _int(rec.get("id.resp_p")),
                "proto": (rec.get("proto") or "TCP").upper(),
                "start_ts": ts,
                "end_ts": ts + duration,
                "duration": duration,
                "packets": _int(rec.get("orig_pkts")),
                "bytes": _int(rec.get("orig_bytes") or rec.get("orig_ip_bytes")),
                "packets_rev": _int(rec.get("resp_pkts")),
                "bytes_rev": _int(rec.get("resp_bytes") or rec.get("resp_ip_bytes")),
                "tcp_state": rec.get("conn_state"),
                "initiator": rec.get("id.orig_h"),
                "l7": rec.get("service") if rec.get("service") not in ("-", None) else None,
                "closed": 1,
            }
        )

    def _zeek_dns(self, line: str) -> None:
        self.__init_caches()
        rec = self._split_zeek(line, self._zcache["dns"])
        if not rec:
            return
        rcode = rec.get("rcode_name") or ""
        if rcode in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
            self.on_alert(
                {
                    "ts": _float(rec.get("ts")),
                    "severity": "low",
                    "signature": f"Zeek DNS {rcode} for {rec.get('query')}",
                    "sid": "zeek-dns-error",
                    "category": "Anomaly",
                    "src_ip": rec.get("id.orig_h"),
                    "dst_ip": rec.get("id.resp_h"),
                    "src_port": _int(rec.get("id.orig_p")),
                    "dst_port": _int(rec.get("id.resp_p")),
                    "proto": (rec.get("proto") or "UDP").upper(),
                    "source": "zeek",
                    "extra": {"query": rec.get("query"), "qtype": rec.get("qtype_name")},
                }
            )

    def _zeek_http(self, line: str) -> None:
        self.__init_caches()
        rec = self._split_zeek(line, self._zcache["http"])
        if not rec:
            return
        code = _int(rec.get("status_code"))
        if code >= 500 or code in (401, 403):
            self.on_alert(
                {
                    "ts": _float(rec.get("ts")),
                    "severity": "medium" if code >= 500 else "low",
                    "signature": f"Zeek HTTP {code} {rec.get('method')} {rec.get('host')}{rec.get('uri')}",
                    "sid": "zeek-http-error",
                    "category": "Web",
                    "src_ip": rec.get("id.orig_h"),
                    "dst_ip": rec.get("id.resp_h"),
                    "src_port": _int(rec.get("id.orig_p")),
                    "dst_port": _int(rec.get("id.resp_p")),
                    "proto": "TCP",
                    "source": "zeek",
                    "extra": {"status": code, "host": rec.get("host"), "uri": rec.get("uri")},
                }
            )

    def _zeek_ssl(self, line: str) -> None:
        # TLS metadata is stored via flow callback when present; no alert by default.
        return

    def _zeek_weird(self, line: str) -> None:
        self.__init_caches()
        rec = self._split_zeek(line, self._zcache["weird"])
        if not rec:
            return
        self.on_alert(
            {
                "ts": _float(rec.get("ts")),
                "severity": "low",
                "signature": f"Zeek weird {rec.get('name')}",
                "sid": "zeek-weird",
                "category": "Anomaly",
                "src_ip": rec.get("id.orig_h"),
                "dst_ip": rec.get("id.resp_h"),
                "source": "zeek",
            }
        )

    def _zeek_notice(self, line: str) -> None:
        self.__init_caches()
        rec = self._split_zeek(line, self._zcache["notice"])
        if not rec:
            return
        self.on_alert(
            {
                "ts": _float(rec.get("ts")),
                "severity": "medium",
                "signature": rec.get("note") or rec.get("msg") or "Zeek notice",
                "sid": "zeek-notice",
                "category": rec.get("note") or "Notice",
                "src_ip": rec.get("id.orig_h") or rec.get("src"),
                "dst_ip": rec.get("id.resp_h") or rec.get("dst"),
                "source": "zeek",
            }
        )

    def _syslog_line(self, line: str) -> None:
        low = line.lower()
        if "denied" in low or "firewall" in low or "ids" in low or "suricata" in low:
            self.on_alert(
                {
                    "ts": time.time(),
                    "severity": "info",
                    "signature": line.strip()[:240],
                    "sid": "syslog",
                    "category": "Syslog",
                    "source": "syslog",
                }
            )


def _int(v: object) -> int | None:
    try:
        if v in (None, "-", ""):
            return None
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def _float(v: object) -> float:
    try:
        return float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return time.time()


def _parse_iso(s: str | None) -> float:
    if not s:
        return time.time()
    try:
        from datetime import datetime

        s2 = s.replace("Z", "+0000")
        # Suricata: 2024-01-01T00:00:00.000000+0000
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(s2, fmt).timestamp()
            except ValueError:
                continue
    except Exception:
        pass
    return time.time()
