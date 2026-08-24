"""Ingest engine: packets -> flows -> detectors -> sqlite, plus KPI sampling."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any

from .capture import CaptureSession
from .config import Settings
from .db import Store
from .detect import Detector
from .flows import FlowTable
from .pcapio import read_pcap
from .parser import parse_frame
from .sensors import SensorHub
from .util import iface_stats

log = logging.getLogger("nids.engine")


class Engine:
    def __init__(self, settings: Settings, store: Store):
        self.settings = settings
        self.store = store
        self.flows = FlowTable(settings.flow_idle_sec, settings.flow_max_sec)
        self.detect = Detector()
        self.capture = CaptureSession(
            self._on_packet,
            iface=settings.iface,
            bpf=settings.bpf,
            store_pcap=settings.store_pcap,
            capture_dir=settings.capture_dir,
            rotate_mb=settings.pcap_rotate_mb,
            rotate_files=settings.pcap_rotate_files,
        )
        self.sensors = SensorHub(self._on_alert, self._on_zeek_flow)
        self._lock = threading.RLock()
        self._pkt_times: deque[float] = deque(maxlen=20_000)
        self._byte_win: deque[tuple[float, int]] = deque(maxlen=20_000)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.started_at = time.time()
        self.packets_total = 0
        self.bytes_total = 0
        self.alerts_total = 0
        self.ws_listeners: list[Any] = []
        self.last_kpi: dict[str, Any] = {}

    def start(self) -> None:
        self._stop.clear()
        self._threads = [
            threading.Thread(target=self._housekeep, daemon=True),
            threading.Thread(target=self._sample, daemon=True),
        ]
        for t in self._threads:
            t.start()
        eve = self.settings.suricata_eve
        zeek = self.settings.zeek_dir
        syslog = self.settings.syslog_path
        # Auto-attach sample sensors if env not set but samples exist
        sample = self.settings.data_dir.parent / "sample"
        if not eve and (sample / "eve.json").exists():
            eve = str(sample / "eve.json")
        if not zeek and (sample / "zeek").exists():
            zeek = str(sample / "zeek")
        started = self.sensors.start(eve_path=eve, zeek_dir=zeek, syslog_path=syslog)
        if started:
            log.info("sensors: %s", started)
        if self.settings.live_enabled:
            try:
                self.capture.start_live()
                self.store.set_sensor(
                    status="live",
                    source=self.capture.source,
                    iface=self.settings.iface,
                    started_at=time.time(),
                    pid=self.capture.proc.pid if self.capture.proc else None,
                    last_error=None,
                )
            except Exception as e:
                log.warning("live capture not started: %s", e)
                self.store.set_sensor(status="error", last_error=str(e), source="live")

    def stop(self) -> None:
        self._stop.set()
        self.capture.stop()
        self.sensors.stop()

    def _on_packet(self, pkt: dict[str, Any]) -> None:
        ts = pkt.get("ts") or time.time()
        length = int(pkt.get("length") or 0)
        fl = self.flows.update(pkt)
        if fl.db_id is None:
            fl.db_id = self.store.upsert_flow(fl.to_row(closed=0))
        pkt["flow_id"] = fl.db_id
        pid = self.store.insert_packet(pkt)
        if pkt.get("payload_hex"):
            self.store.execute(
                "INSERT OR REPLACE INTO packet_payloads (packet_id, hex, ascii) VALUES (?,?,?)",
                (pid, pkt.get("payload_hex"), pkt.get("payload_ascii")),
            )
        self.store.bump_host(pkt.get("src_ip"), ts, "out", length, pkt.get("dst_port"))
        self.store.bump_host(pkt.get("dst_ip"), ts, "in", length, pkt.get("src_port"))
        for a in self.detect.on_packet(pkt):
            a["flow_id"] = fl.db_id
            a["packet_id"] = pid
            self._on_alert(a)
        with self._lock:
            self.packets_total += 1
            self.bytes_total += length
            self._pkt_times.append(ts)
            self._byte_win.append((ts, length))

    def _on_alert(self, a: dict[str, Any]) -> None:
        self.store.insert_alert(a)
        self.alerts_total += 1
        if a.get("src_ip"):
            self.store.execute(
                "UPDATE hosts SET alert_count=alert_count+1 WHERE ip=?",
                (a["src_ip"],),
            )

    def _on_zeek_flow(self, f: dict[str, Any]) -> None:
        self.store.upsert_flow(f)

    def ingest_pcap_file(self, path: str, replace: bool = False) -> dict[str, int]:
        from pathlib import Path

        p = Path(path)
        if replace:
            self.store.wipe_telemetry()
            self.flows = FlowTable(self.settings.flow_idle_sec, self.settings.flow_max_sec)
            self.detect = Detector()
        n = 0
        for ts, frame in read_pcap(p):
            pkt = parse_frame(
                ts,
                frame,
                store_payload=self.settings.payload_enabled,
                payload_max=self.settings.payload_max_bytes,
            )
            if not pkt:
                continue
            self._on_packet(pkt)
            n += 1
        for fl in self.flows.expire(time.time() + 90):
            self.store.upsert_flow(fl.to_row(closed=1))
            for a in self.detect.on_flow(fl):
                a["flow_id"] = fl.db_id
                self._on_alert(a)
        return {"packets": n}

    def start_live(self, iface: str | None = None, bpf: str | None = None) -> dict:
        if iface:
            self.settings.iface = iface
            self.capture.iface = iface
        if bpf is not None:
            self.settings.bpf = bpf
            self.capture.bpf = bpf
        self.capture.start_live()
        self.store.set_sensor(
            status="live",
            source=self.capture.source,
            iface=self.capture.iface,
            started_at=time.time(),
            pid=self.capture.proc.pid if self.capture.proc else None,
            last_error=None,
        )
        return self.capture.status()

    def stop_live(self) -> dict:
        self.capture.stop()
        self.store.set_sensor(status="idle", pid=None, source="idle")
        return self.capture.status()

    def _housekeep(self) -> None:
        while not self._stop.wait(2.0):
            try:
                closed = self.flows.expire()
                for fl in closed:
                    self.store.upsert_flow(fl.to_row(closed=1))
                    for a in self.detect.on_flow(fl):
                        a["flow_id"] = fl.db_id
                        self._on_alert(a)
                for a in self.detect.scan_windows():
                    self._on_alert(a)
                # persist open flows periodically
                for fl in self.flows.active()[:200]:
                    self.store.upsert_flow(fl.to_row(closed=0))
                self.store.prune(
                    self.settings.max_packets,
                    self.settings.max_flows,
                    self.settings.max_alerts,
                    self.settings.stats_keep_hours,
                )
            except Exception:
                log.exception("housekeep failed")

    def _sample(self) -> None:
        prev_pkts = 0
        prev_bytes = 0
        prev_alerts = 0
        prev_t = time.time()
        while not self._stop.wait(1.0):
            try:
                now = time.time()
                dt = max(0.001, now - prev_t)
                pkts = self.packets_total
                by = self.bytes_total
                al = self.alerts_total
                pps = (pkts - prev_pkts) / dt
                bps = ((by - prev_bytes) * 8) / dt
                alert_rate = (al - prev_alerts) / dt
                prev_pkts, prev_bytes, prev_alerts, prev_t = pkts, by, al, now
                new_flows = self.flows.pop_new()
                # new dests in last second approximated by detector known growth — skip, use 0
                ist = iface_stats(self.settings.iface)
                drops = ist.get("rx_dropped") or self.capture.drops
                errors = ist.get("rx_errors") or 0
                unique_hosts = self.store.scalar("SELECT COUNT(*) FROM hosts")
                row = {
                    "ts": now,
                    "pps": pps,
                    "bps": bps,
                    "flows_active": len(self.flows.active()),
                    "flows_new": new_flows,
                    "alert_rate": alert_rate,
                    "unique_hosts": unique_hosts,
                    "drops": drops,
                    "errors": errors,
                    "packets_total": pkts,
                    "bytes_total": by,
                }
                # If we are sitting on demo data with no live packets, keep sampling zeros
                # but do not flood stats_ts when idle — still write so charts have a live edge.
                self.store.insert_stats(row)
                for a in self.detect.volume_anomalies(pps, new_flows):
                    self._on_alert(a)
                self.last_kpi = row
                self.store.set_sensor(
                    packets=self.capture.packets or pkts,
                    drops=drops,
                    errors=errors,
                    last_error=self.capture.last_error,
                )
            except Exception:
                log.exception("sample failed")

    def kpis(self, t0: float, t1: float) -> dict[str, Any]:
        live = self.last_kpi or {}
        pkt_n = self.store.scalar(
            "SELECT COUNT(*) FROM packets WHERE ts BETWEEN ? AND ?", (t0, t1)
        )
        byte_n = self.store.scalar(
            "SELECT COALESCE(SUM(length),0) FROM packets WHERE ts BETWEEN ? AND ?", (t0, t1)
        )
        span = max(1.0, t1 - t0)
        alerts = self.store.scalar(
            "SELECT COUNT(*) FROM alerts WHERE ts BETWEEN ? AND ? AND muted=0", (t0, t1)
        )
        hosts = self.store.scalar(
            "SELECT COUNT(*) FROM hosts WHERE last_seen BETWEEN ? AND ?", (t0, t1)
        )
        flows = self.store.scalar(
            "SELECT COUNT(*) FROM flows WHERE start_ts <= ? AND end_ts >= ?", (t1, t0)
        )
        drops = live.get("drops") or 0
        errors = live.get("errors") or 0
        return {
            "pps": live.get("pps") if (live.get("pps") or 0) > 0 else pkt_n / span,
            "bps": live.get("bps") if (live.get("bps") or 0) > 0 else (byte_n * 8) / span,
            "active_flows": live.get("flows_active") or flows,
            "alert_rate": live.get("alert_rate") if live.get("alert_rate") else alerts / span,
            "unique_hosts": hosts,
            "drops": drops,
            "errors": errors,
            "packets": pkt_n,
            "bytes": byte_n,
            "alerts": alerts,
            "sensor_uptime": time.time() - self.started_at,
        }
