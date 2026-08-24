"""Statistical / behavioral detectors. These are heuristics, not a Suricata replacement.

Alerts describe observed patterns (scans, floods, beacons, volume outliers).
No exploit payloads, shellcode, or attack how-tos are generated.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Iterable

from .flows import Flow
from .util import flags_str

# Local SID space 9yards: 9000000+
SID_PORT_SCAN = "9000001"
SID_HOST_SCAN = "9000002"
SID_SYN_BURST = "9000003"
SID_ELEPHANT = "9000004"
SID_RST_RATE = "9000005"
SID_DNS_BURST = "9000006"
SID_BEACON = "9000007"
SID_ICMP_BURST = "9000008"
SID_NEW_DST = "9000009"
SID_RARE_PORT = "9000010"
SID_NULL_SCAN = "9000011"
SID_FIN_SCAN = "9000012"


def _alert(**kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("source", "stat")
    kwargs.setdefault("is_demo", False)
    kwargs.setdefault("count", 1)
    kwargs.setdefault("ts", time.time())
    return kwargs


class Detector:
    def __init__(self) -> None:
        self._syn_win: dict[str, deque[float]] = defaultdict(deque)
        self._icmp_win: dict[str, deque[float]] = defaultdict(deque)
        self._dns_win: dict[str, deque[float]] = defaultdict(deque)
        self._dsts: dict[str, dict[str, float]] = defaultdict(dict)  # src -> dst -> last ts
        self._ports: dict[tuple[str, str], set[int]] = defaultdict(set)  # (src,dst) -> ports
        self._hosts_contacted: dict[str, set[str]] = defaultdict(set)
        self._conn_times: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._pps_hist: deque[float] = deque(maxlen=60)
        self._new_dst_hist: deque[int] = deque(maxlen=60)
        self.known_dsts: set[str] = set()

    def on_packet(self, pkt: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        ts = pkt.get("ts") or time.time()
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")
        flags_raw = pkt.get("tcp_flags")
        flags = flags_raw or 0
        proto = pkt.get("proto")
        if src and dst:
            self._dsts[src][dst] = ts
            self._hosts_contacted[src].add(dst)
            if dst not in self.known_dsts:
                self.known_dsts.add(dst)
        if src and dst and pkt.get("dst_port"):
            self._ports[(src, dst)].add(int(pkt["dst_port"]))

        # SYN burst (no ACK bit, SYN set)
        if proto == "TCP" and flags & 0x02 and not (flags & 0x10):
            q = self._syn_win[src or ""]
            q.append(ts)
            while q and ts - q[0] > 2.0:
                q.popleft()
            if len(q) >= 80:
                alerts.append(
                    _alert(
                        sid=SID_SYN_BURST,
                        signature="STAT TCP SYN burst (possible flood or scan)",
                        category="Denial of Service",
                        severity="high",
                        src_ip=src,
                        dst_ip=dst,
                        src_port=pkt.get("src_port"),
                        dst_port=pkt.get("dst_port"),
                        proto="TCP",
                        count=len(q),
                        extra={"syn_per_2s": len(q)},
                    )
                )
                q.clear()

        if proto == "ICMP":
            q = self._icmp_win[src or ""]
            q.append(ts)
            while q and ts - q[0] > 2.0:
                q.popleft()
            if len(q) >= 60:
                alerts.append(
                    _alert(
                        sid=SID_ICMP_BURST,
                        signature="STAT ICMP echo burst",
                        category="Denial of Service",
                        severity="medium",
                        src_ip=src,
                        dst_ip=dst,
                        proto="ICMP",
                        count=len(q),
                    )
                )
                q.clear()

        if pkt.get("l7") == "dns" and src:
            q = self._dns_win[src]
            q.append(ts)
            while q and ts - q[0] > 2.0:
                q.popleft()
            if len(q) >= 40:
                alerts.append(
                    _alert(
                        sid=SID_DNS_BURST,
                        signature="STAT DNS query burst",
                        category="Anomaly",
                        severity="medium",
                        src_ip=src,
                        dst_ip=dst,
                        proto="UDP",
                        count=len(q),
                        extra={"qname": pkt.get("info")},
                    )
                )
                q.clear()

        # Unusual TCP flag combinations (explicit 0 = NULL, not missing)
        if proto == "TCP" and flags_raw is not None:
            if flags_raw == 0:
                alerts.append(
                    _alert(
                        sid=SID_NULL_SCAN,
                        signature="STAT TCP NULL flags (no bits set)",
                        category="Reconnaissance",
                        severity="medium",
                        src_ip=src,
                        dst_ip=dst,
                        src_port=pkt.get("src_port"),
                        dst_port=pkt.get("dst_port"),
                        proto="TCP",
                    )
                )
            if flags == 0x01:  # FIN only
                alerts.append(
                    _alert(
                        sid=SID_FIN_SCAN,
                        signature="STAT TCP FIN-only (possible FIN scan)",
                        category="Reconnaissance",
                        severity="medium",
                        src_ip=src,
                        dst_ip=dst,
                        src_port=pkt.get("src_port"),
                        dst_port=pkt.get("dst_port"),
                        proto="TCP",
                    )
                )
        return alerts

    def on_flow(self, fl: Flow) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        total_pkts = fl.packets + fl.packets_rev
        total_bytes = fl.bytes + fl.bytes_rev
        # Elephant flow
        if total_bytes >= 2_000_000 or (fl.duration > 5 and total_bytes >= 800_000):
            alerts.append(
                _alert(
                    sid=SID_ELEPHANT,
                    signature="STAT Elephant flow (high byte volume)",
                    category="Anomaly",
                    severity="info",
                    src_ip=fl.src_ip,
                    dst_ip=fl.dst_ip,
                    src_port=fl.src_port,
                    dst_port=fl.dst_port,
                    proto=fl.proto,
                    extra={"bytes": total_bytes, "duration": fl.duration},
                    ts=fl.end_ts,
                )
            )
        # RST-heavy conversation
        if total_pkts >= 8 and fl.rst_count / max(total_pkts, 1) >= 0.4:
            alerts.append(
                _alert(
                    sid=SID_RST_RATE,
                    signature="STAT High TCP reset rate on flow",
                    category="Anomaly",
                    severity="low",
                    src_ip=fl.src_ip,
                    dst_ip=fl.dst_ip,
                    src_port=fl.src_port,
                    dst_port=fl.dst_port,
                    proto=fl.proto,
                    extra={"rst": fl.rst_count, "packets": total_pkts, "flags": flags_str(fl.tcp_flags)},
                    ts=fl.end_ts,
                )
            )
        # Rare high port used as server with many SYNs and little data
        if fl.proto == "TCP" and fl.dst_port and fl.dst_port >= 10000:
            if fl.syn_count >= 4 and total_bytes < 400:
                alerts.append(
                    _alert(
                        sid=SID_RARE_PORT,
                        signature="STAT Repeated SYNs to high/ephemeral port",
                        category="Reconnaissance",
                        severity="low",
                        src_ip=fl.src_ip,
                        dst_ip=fl.dst_ip,
                        src_port=fl.src_port,
                        dst_port=fl.dst_port,
                        proto="TCP",
                        ts=fl.end_ts,
                    )
                )
        # Beaconing: record orig->resp times
        pair = (fl.src_ip, fl.dst_ip)
        self._conn_times[pair].append(fl.start_ts)
        times = self._conn_times[pair][-20:]
        self._conn_times[pair] = times
        if len(times) >= 6:
            deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
            if deltas:
                mean = sum(deltas) / len(deltas)
                if 5 <= mean <= 180:
                    var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
                    if var < (mean * 0.15) ** 2:
                        alerts.append(
                            _alert(
                                sid=SID_BEACON,
                                signature="STAT Periodic connection interval (possible beacon)",
                                category="C2",
                                severity="high",
                                src_ip=fl.src_ip,
                                dst_ip=fl.dst_ip,
                                src_port=fl.src_port,
                                dst_port=fl.dst_port,
                                proto=fl.proto,
                                extra={"interval_s": round(mean, 2), "samples": len(deltas)},
                                ts=fl.end_ts,
                            )
                        )
        return alerts

    def scan_windows(self, now: float | None = None) -> list[dict[str, Any]]:
        """Vertical/horizontal scan detection over recently observed maps."""
        now = now or time.time()
        alerts: list[dict[str, Any]] = []
        # vertical: many ports on one dest
        for (src, dst), ports in list(self._ports.items()):
            if len(ports) >= 18:
                alerts.append(
                    _alert(
                        sid=SID_PORT_SCAN,
                        signature="STAT Vertical port scan (many dest ports, few packets implied)",
                        category="Reconnaissance",
                        severity="high",
                        src_ip=src,
                        dst_ip=dst,
                        proto="TCP",
                        count=len(ports),
                        extra={"unique_ports": len(ports)},
                        ts=now,
                    )
                )
                self._ports[(src, dst)] = set()
        # horizontal: many destinations
        for src, dsts in list(self._hosts_contacted.items()):
            if len(dsts) >= 20:
                alerts.append(
                    _alert(
                        sid=SID_HOST_SCAN,
                        signature="STAT Horizontal host scan (many destinations)",
                        category="Reconnaissance",
                        severity="high",
                        src_ip=src,
                        proto="TCP",
                        count=len(dsts),
                        extra={"unique_dsts": len(dsts)},
                        ts=now,
                    )
                )
                self._hosts_contacted[src] = set()
        return alerts

    def volume_anomalies(self, pps: float, new_dsts: int) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        if len(self._pps_hist) >= 15:
            m = sum(self._pps_hist) / len(self._pps_hist)
            var = sum((x - m) ** 2 for x in self._pps_hist) / len(self._pps_hist)
            s = var ** 0.5
            if s > 1 and pps > m + 3.5 * s and pps > 200:
                alerts.append(
                    _alert(
                        sid="9000013",
                        signature="STAT Packet-rate z-score spike",
                        category="Anomaly",
                        severity="medium",
                        extra={"pps": pps, "baseline": round(m, 2), "z": round((pps - m) / s, 2)},
                    )
                )
        self._pps_hist.append(pps)
        if len(self._new_dst_hist) >= 15:
            m = sum(self._new_dst_hist) / len(self._new_dst_hist)
            if new_dsts > max(20, m * 4 + 10):
                alerts.append(
                    _alert(
                        sid=SID_NEW_DST,
                        signature="STAT New-destination spike vs rolling baseline",
                        category="Anomaly",
                        severity="medium",
                        extra={"new_dsts": new_dsts, "baseline": round(m, 2)},
                    )
                )
        self._new_dst_hist.append(new_dsts)
        return alerts


def scan_like_sql_hint() -> str:
    """Flows that look like scans: many dests/ports, few packets, low bytes."""
    return """
      (packets + packets_rev) <= 3
      AND (bytes + bytes_rev) <= 240
      AND proto = 'TCP'
      AND syn_count >= 1
    """
