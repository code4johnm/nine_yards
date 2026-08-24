"""Bidirectional flow tracker (Zeek-style orig/resp)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .util import flags_str


def _canon(src_ip: str, dst_ip: str, sport: int | None, dport: int | None, proto: str) -> tuple:
    a = (src_ip or "", sport or 0)
    b = (dst_ip or "", dport or 0)
    if a <= b:
        return (a[0], b[0], a[1], b[1], proto, False)
    return (b[0], a[0], b[1], a[1], proto, True)


TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_PSH = 0x08


def _state(flags_or: int, syn: int, fin: int, rst: int, seen_ack: bool) -> str:
    if rst:
        return "RST"
    if fin >= 2:
        return "CLOSED"
    if fin == 1:
        return "FIN_WAIT"
    if syn and seen_ack and (flags_or & TCP_ACK):
        return "ESTABLISHED"
    if syn and not seen_ack:
        return "SYN_SENT"
    if syn:
        return "SYN"
    if flags_or & TCP_ACK:
        return "ACK"
    return "OTHER"


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str
    start_ts: float
    end_ts: float
    packets: int = 0
    bytes: int = 0
    packets_rev: int = 0
    bytes_rev: int = 0
    tcp_flags: int = 0
    initiator: str = ""
    rst_count: int = 0
    retrans_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    l7: str | None = None
    sni: str | None = None
    ja3: str | None = None
    db_id: int | None = None
    seq_seen: dict[str, set[int]] = field(default_factory=dict)
    seen_ack: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def tcp_state(self) -> str:
        return _state(self.tcp_flags, self.syn_count, self.fin_count, self.rst_count, self.seen_ack)

    def to_row(self, closed: int = 0) -> dict[str, Any]:
        return {
            "id": self.db_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration": self.duration,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_rev": self.packets_rev,
            "bytes_rev": self.bytes_rev,
            "tcp_flags": self.tcp_flags,
            "tcp_state": self.tcp_state,
            "initiator": self.initiator,
            "rst_count": self.rst_count,
            "retrans_count": self.retrans_count,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "closed": closed,
            "l7": self.l7,
            "sni": self.sni,
            "ja3": self.ja3,
        }


class FlowTable:
    def __init__(self, idle_sec: float = 60.0, max_sec: float = 600.0):
        self.idle_sec = idle_sec
        self.max_sec = max_sec
        self._lock = threading.RLock()
        self._flows: dict[tuple, Flow] = {}
        self.new_since_tick = 0

    def update(self, pkt: dict[str, Any]) -> Flow:
        proto = pkt.get("proto") or "OTHER"
        src_ip = pkt.get("src_ip") or ""
        dst_ip = pkt.get("dst_ip") or ""
        sport = pkt.get("src_port")
        dport = pkt.get("dst_port")
        key_src, key_dst, key_sp, key_dp, key_pr, reversed_ = _canon(src_ip, dst_ip, sport, dport, proto)
        key = (key_src, key_dst, key_sp, key_dp, key_pr)
        ts = pkt.get("ts") or time.time()
        length = int(pkt.get("length") or 0)
        flags = pkt.get("tcp_flags") or 0
        with self._lock:
            fl = self._flows.get(key)
            if fl is None:
                # initiator is the first packet's src, stored as orig=src_ip
                orig_ip, resp_ip = src_ip, dst_ip
                orig_sp, orig_dp = sport, dport
                fl = Flow(
                    src_ip=orig_ip,
                    dst_ip=resp_ip,
                    src_port=orig_sp,
                    dst_port=orig_dp,
                    proto=proto,
                    start_ts=ts,
                    end_ts=ts,
                    initiator=src_ip,
                )
                self._flows[key] = fl
                self.new_since_tick += 1
            fl.end_ts = ts
            if reversed_:
                fl.packets_rev += 1
                fl.bytes_rev += length
            else:
                fl.packets += 1
                fl.bytes += length
            if flags:
                fl.tcp_flags |= flags
                if flags & TCP_SYN:
                    fl.syn_count += 1
                if flags & TCP_FIN:
                    fl.fin_count += 1
                if flags & TCP_RST:
                    fl.rst_count += 1
                if flags & TCP_ACK:
                    fl.seen_ack = True
            seq = pkt.get("tcp_seq")
            if seq is not None and proto == "TCP":
                bucket = fl.seq_seen.setdefault(pkt.get("src_ip") or "", set())
                if seq in bucket:
                    fl.retrans_count += 1
                    pkt["is_retrans"] = 1
                else:
                    if len(bucket) > 400:
                        bucket.clear()
                    bucket.add(seq)
            if pkt.get("is_retrans"):
                fl.retrans_count += 1
            if pkt.get("l7") and pkt["l7"] not in ("tcp", "udp", "unknown"):
                fl.l7 = pkt["l7"]
            if pkt.get("sni"):
                fl.sni = pkt["sni"]
            if pkt.get("ja3"):
                fl.ja3 = pkt["ja3"]
            return fl

    def expire(self, now: float | None = None) -> list[Flow]:
        now = now or time.time()
        closed: list[Flow] = []
        with self._lock:
            drop = []
            for key, fl in self._flows.items():
                idle = now - fl.end_ts
                age = now - fl.start_ts
                done = False
                if fl.proto == "TCP" and (fl.rst_count or fl.fin_count >= 2):
                    if idle > 1.0:
                        done = True
                if idle > self.idle_sec or age > self.max_sec:
                    done = True
                if done:
                    drop.append(key)
                    closed.append(fl)
            for key in drop:
                self._flows.pop(key, None)
        return closed

    def active(self) -> list[Flow]:
        with self._lock:
            return list(self._flows.values())

    def pop_new(self) -> int:
        with self._lock:
            n = self.new_since_tick
            self.new_since_tick = 0
            return n

    def snapshot_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return [fl.to_row(closed=0) for fl in self._flows.values()]
