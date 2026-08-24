"""SQLite WAL store for packets, flows, alerts, stats, hosts, settings."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

from .util import iso

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA temp_store=MEMORY;
PRAGMA busy_timeout=8000;

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_mac TEXT,
    dst_mac TEXT,
    vlan INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT,
    ip_proto INTEGER,
    length INTEGER,
    tcp_flags INTEGER,
    ttl INTEGER,
    l7 TEXT,
    flow_id INTEGER,
    is_retrans INTEGER DEFAULT 0,
    payload_len INTEGER DEFAULT 0,
    info TEXT,
    ja3 TEXT,
    sni TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_id);
CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(proto);

CREATE TABLE IF NOT EXISTS packet_payloads (
    packet_id INTEGER PRIMARY KEY,
    hex TEXT,
    ascii TEXT,
    FOREIGN KEY(packet_id) REFERENCES packets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT NOT NULL,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    duration REAL,
    packets INTEGER DEFAULT 0,
    bytes INTEGER DEFAULT 0,
    packets_rev INTEGER DEFAULT 0,
    bytes_rev INTEGER DEFAULT 0,
    tcp_flags INTEGER DEFAULT 0,
    tcp_state TEXT,
    initiator TEXT,
    rst_count INTEGER DEFAULT 0,
    retrans_count INTEGER DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    fin_count INTEGER DEFAULT 0,
    closed INTEGER DEFAULT 0,
    l7 TEXT,
    sni TEXT,
    ja3 TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_start ON flows(start_ts);
CREATE INDEX IF NOT EXISTS idx_flows_end ON flows(end_ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_bytes ON flows(bytes);
CREATE INDEX IF NOT EXISTS idx_flows_tuple
    ON flows(src_ip, dst_ip, src_port, dst_port, proto, closed);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    severity TEXT NOT NULL,
    signature TEXT NOT NULL,
    sid TEXT,
    category TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT,
    count INTEGER DEFAULT 1,
    flow_id INTEGER,
    packet_id INTEGER,
    source TEXT,
    is_demo INTEGER DEFAULT 0,
    acked INTEGER DEFAULT 0,
    muted INTEGER DEFAULT 0,
    comment TEXT,
    extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_sig ON alerts(signature);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(sid, src_ip, dst_ip, muted, acked);

CREATE TABLE IF NOT EXISTS stats_ts (
    ts REAL PRIMARY KEY,
    pps REAL,
    bps REAL,
    flows_active INTEGER,
    flows_new INTEGER,
    alert_rate REAL,
    unique_hosts INTEGER,
    drops INTEGER,
    errors INTEGER,
    packets_total INTEGER,
    bytes_total INTEGER
);

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    first_seen REAL,
    last_seen REAL,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    packets_in INTEGER DEFAULT 0,
    packets_out INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    ports TEXT,
    tldn TEXT
);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT
);

CREATE TABLE IF NOT EXISTS sensor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    iface TEXT,
    started_at REAL,
    pid INTEGER,
    status TEXT,
    packets INTEGER DEFAULT 0,
    drops INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    source TEXT,
    last_error TEXT
);
INSERT OR IGNORE INTO sensor (id, status, source) VALUES (1, 'idle', 'demo');
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
        self._migrate()
        self.backfill_tldn()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.query("PRAGMA table_info(hosts)")}
        if "tldn" not in cols:
            self.execute("ALTER TABLE hosts ADD COLUMN tldn TEXT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def execute(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(args))

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, list(rows))

    def query(self, sql: str, args: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            cols = [c[0] for c in cur.description] if cur.description else []
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def query_one(self, sql: str, args: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def scalar(self, sql: str, args: Iterable[Any] = (), default: Any = 0) -> Any:
        row = self.query_one(sql, args)
        if not row:
            return default
        return next(iter(row.values()))

    def iter_query(self, sql: str, args: Iterable[Any] = ()) -> Iterator[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            cols = [c[0] for c in cur.description] if cur.description else []
            for row in cur:
                yield dict(zip(cols, row))

    # --- packets / flows ---

    def insert_packet(self, p: dict[str, Any]) -> int:
        cols = [
            "ts", "src_mac", "dst_mac", "vlan", "src_ip", "dst_ip", "src_port", "dst_port",
            "proto", "ip_proto", "length", "tcp_flags", "ttl", "l7", "flow_id",
            "is_retrans", "payload_len", "info", "ja3", "sni",
        ]
        vals = [p.get(c) for c in cols]
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO packets ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                vals,
            )
            return int(cur.lastrowid)

    def insert_packets(self, packets: list[dict[str, Any]]) -> list[int]:
        ids = []
        with self._lock:
            cols = [
                "ts", "src_mac", "dst_mac", "vlan", "src_ip", "dst_ip", "src_port", "dst_port",
                "proto", "ip_proto", "length", "tcp_flags", "ttl", "l7", "flow_id",
                "is_retrans", "payload_len", "info", "ja3", "sni",
            ]
            sql = f"INSERT INTO packets ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})"
            for p in packets:
                cur = self._conn.execute(sql, [p.get(c) for c in cols])
                pid = int(cur.lastrowid)
                ids.append(pid)
                if p.get("payload_hex") or p.get("payload_ascii"):
                    self._conn.execute(
                        "INSERT OR REPLACE INTO packet_payloads (packet_id, hex, ascii) VALUES (?,?,?)",
                        (pid, p.get("payload_hex"), p.get("payload_ascii")),
                    )
        return ids

    def upsert_flow(self, f: dict[str, Any]) -> int:
        existing = None
        if f.get("id"):
            existing = self.query_one("SELECT id FROM flows WHERE id=?", (f["id"],))
        if not existing:
            existing = self.query_one(
                """SELECT id FROM flows WHERE src_ip=? AND dst_ip=? AND IFNULL(src_port,-1)=IFNULL(?, -1)
                   AND IFNULL(dst_port,-1)=IFNULL(?, -1) AND proto=? AND closed=0""",
                (f["src_ip"], f["dst_ip"], f.get("src_port"), f.get("dst_port"), f["proto"]),
            )
        cols = [
            "src_ip", "dst_ip", "src_port", "dst_port", "proto", "start_ts", "end_ts", "duration",
            "packets", "bytes", "packets_rev", "bytes_rev", "tcp_flags", "tcp_state", "initiator",
            "rst_count", "retrans_count", "syn_count", "fin_count", "closed", "l7", "sni", "ja3",
        ]
        if existing:
            fid = existing["id"]
            sets = ",".join(f"{c}=?" for c in cols)
            self.execute(f"UPDATE flows SET {sets} WHERE id=?", [f.get(c) for c in cols] + [fid])
            return fid
        placeholders = ",".join("?" for _ in cols)
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO flows ({','.join(cols)}) VALUES ({placeholders})",
                [f.get(c) for c in cols],
            )
            return int(cur.lastrowid)

    def close_idle_flows(self, idle_sec: float, max_sec: float, now: float | None = None) -> list[int]:
        now = now or time.time()
        rows = self.query(
            "SELECT id FROM flows WHERE closed=0 AND (end_ts < ? OR start_ts < ?)",
            (now - idle_sec, now - max_sec),
        )
        ids = [r["id"] for r in rows]
        if ids:
            self.execute(
                f"UPDATE flows SET closed=1, duration=end_ts-start_ts WHERE id IN ({','.join('?' for _ in ids)})",
                ids,
            )
        return ids

    def insert_alert(self, a: dict[str, Any], dedup_window: float = 120.0) -> int:
        now = a.get("ts") or time.time()
        sid = a.get("sid")
        src = a.get("src_ip")
        dst = a.get("dst_ip")
        existing = self.query_one(
            """SELECT id, count FROM alerts
               WHERE sid=? AND IFNULL(src_ip,'')=IFNULL(?, '') AND IFNULL(dst_ip,'')=IFNULL(?, '')
                 AND last_seen >= ? AND muted=0""",
            (sid, src, dst, now - dedup_window),
        )
        extra = a.get("extra")
        if isinstance(extra, (dict, list)):
            extra = json.dumps(extra)
        if existing:
            self.execute(
                "UPDATE alerts SET last_seen=?, count=count+?, ts=? WHERE id=?",
                (now, a.get("count") or 1, now, existing["id"]),
            )
            return int(existing["id"])
        cols = [
            "ts", "first_seen", "last_seen", "severity", "signature", "sid", "category",
            "src_ip", "dst_ip", "src_port", "dst_port", "proto", "count", "flow_id",
            "packet_id", "source", "is_demo", "acked", "muted", "comment", "extra",
        ]
        payload = {
            "ts": now,
            "first_seen": a.get("first_seen", now),
            "last_seen": a.get("last_seen", now),
            "severity": a.get("severity", "info"),
            "signature": a.get("signature", "unknown"),
            "sid": sid,
            "category": a.get("category"),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": a.get("src_port"),
            "dst_port": a.get("dst_port"),
            "proto": a.get("proto"),
            "count": a.get("count") or 1,
            "flow_id": a.get("flow_id"),
            "packet_id": a.get("packet_id"),
            "source": a.get("source", "stat"),
            "is_demo": 1 if a.get("is_demo") else 0,
            "acked": 0,
            "muted": 0,
            "comment": a.get("comment"),
            "extra": extra,
        }
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [payload[c] for c in cols],
            )
            return int(cur.lastrowid)

    def bump_host(self, ip: str | None, ts: float, direction: str, length: int, port: int | None) -> None:
        if not ip:
            return
        row = self.query_one("SELECT ip, ports FROM hosts WHERE ip=?", (ip,))
        ports: list[str] = []
        if row and row.get("ports"):
            try:
                ports = json.loads(row["ports"])
            except json.JSONDecodeError:
                ports = []
        if port and str(port) not in ports:
            ports.append(str(port))
            ports = ports[-40:]
        bins = json.dumps(ports)
        if not row:
            self.execute(
                """INSERT INTO hosts (ip, first_seen, last_seen, bytes_in, bytes_out, packets_in, packets_out, ports, tldn)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ip, ts, ts,
                    length if direction == "in" else 0,
                    length if direction == "out" else 0,
                    1 if direction == "in" else 0,
                    1 if direction == "out" else 0,
                    bins,
                    None,
                ),
            )
            return
        if direction == "in":
            self.execute(
                """UPDATE hosts SET last_seen=?, bytes_in=bytes_in+?, packets_in=packets_in+1, ports=?
                   WHERE ip=?""",
                (ts, length, bins, ip),
            )
        else:
            self.execute(
                """UPDATE hosts SET last_seen=?, bytes_out=bytes_out+?, packets_out=packets_out+1, ports=?
                   WHERE ip=?""",
                (ts, length, bins, ip),
            )

    def set_host_tldn(self, ip: str | None, name: str | None) -> None:
        from .util import clean_hostname
        host = clean_hostname(name)
        addr = (ip or "").strip()
        if not addr or not host:
            return
        row = self.query_one("SELECT ip, tldn FROM hosts WHERE ip=?", (addr,))
        now = time.time()
        if not row:
            self.execute(
                """INSERT INTO hosts (ip, first_seen, last_seen, tldn)
                   VALUES (?,?,?,?)""",
                (addr, now, now, host),
            )
            return
        if row.get("tldn"):
            return
        self.execute("UPDATE hosts SET tldn=? WHERE ip=?", (host, addr))

    def tldn_map(self, ips: Iterable[str]) -> dict[str, str]:
        addrs = [i for i in dict.fromkeys(ips) if i]
        if not addrs:
            return {}
        out: dict[str, str] = {}
        chunk = 400
        for i in range(0, len(addrs), chunk):
            part = addrs[i : i + chunk]
            q = ",".join("?" for _ in part)
            for row in self.query(f"SELECT ip, tldn FROM hosts WHERE ip IN ({q}) AND IFNULL(tldn,'') != ''", part):
                out[row["ip"]] = row["tldn"]
        return out

    def backfill_tldn(self) -> None:
        self.execute(
            """UPDATE hosts SET tldn = (
                   SELECT f.sni FROM flows f
                   WHERE f.dst_ip = hosts.ip AND IFNULL(f.sni,'') != ''
                   LIMIT 1
               )
               WHERE IFNULL(tldn,'') = ''
                 AND EXISTS (SELECT 1 FROM flows f WHERE f.dst_ip = hosts.ip AND IFNULL(f.sni,'') != '')"""
        )
        self.execute(
            """UPDATE hosts SET tldn = (
                   SELECT p.sni FROM packets p
                   WHERE p.dst_ip = hosts.ip AND IFNULL(p.sni,'') != ''
                   LIMIT 1
               )
               WHERE IFNULL(tldn,'') = ''
                 AND EXISTS (SELECT 1 FROM packets p WHERE p.dst_ip = hosts.ip AND IFNULL(p.sni,'') != '')"""
        )
        rows = self.query(
            """SELECT dst_ip, info FROM packets
               WHERE info LIKE '%host=%' AND dst_ip IS NOT NULL
               LIMIT 4000"""
        )
        from .util import clean_hostname
        for r in rows:
            info = r.get("info") or ""
            host = None
            for part in info.split():
                if part.lower().startswith("host="):
                    host = clean_hostname(part.split("=", 1)[1])
                    break
            if host:
                self.set_host_tldn(r.get("dst_ip"), host)

    def insert_stats(self, row: dict[str, Any]) -> None:
        self.execute(
            """INSERT OR REPLACE INTO stats_ts
               (ts, pps, bps, flows_active, flows_new, alert_rate, unique_hosts, drops, errors, packets_total, bytes_total)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["ts"], row.get("pps"), row.get("bps"), row.get("flows_active"), row.get("flows_new"),
                row.get("alert_rate"), row.get("unique_hosts"), row.get("drops"), row.get("errors"),
                row.get("packets_total"), row.get("bytes_total"),
            ),
        )

    def set_kv(self, k: str, v: Any) -> None:
        if not isinstance(v, str):
            v = json.dumps(v)
        self.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?,?)", (k, v))

    def get_kv(self, k: str, default: Any = None) -> Any:
        row = self.query_one("SELECT v FROM kv WHERE k=?", (k,))
        if not row:
            return default
        v = row["v"]
        try:
            return json.loads(v)
        except (TypeError, json.JSONDecodeError):
            return v

    def set_sensor(self, **kwargs: Any) -> None:
        if not kwargs:
            return
        sets = ",".join(f"{k}=?" for k in kwargs)
        self.execute(f"UPDATE sensor SET {sets} WHERE id=1", list(kwargs.values()))

    def get_sensor(self) -> dict[str, Any]:
        return self.query_one("SELECT * FROM sensor WHERE id=1") or {}

    def prune(self, max_packets: int, max_flows: int, max_alerts: int, stats_keep_hours: int) -> None:
        n = self.scalar("SELECT COUNT(*) FROM packets")
        if n > max_packets:
            extra = n - max_packets
            self.execute(
                "DELETE FROM packets WHERE id IN (SELECT id FROM packets ORDER BY ts ASC LIMIT ?)",
                (extra,),
            )
        n = self.scalar("SELECT COUNT(*) FROM flows")
        if n > max_flows:
            extra = n - max_flows
            self.execute(
                "DELETE FROM flows WHERE id IN (SELECT id FROM flows WHERE closed=1 ORDER BY end_ts ASC LIMIT ?)",
                (extra,),
            )
        n = self.scalar("SELECT COUNT(*) FROM alerts")
        if n > max_alerts:
            extra = n - max_alerts
            self.execute(
                "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE acked=1 OR muted=1 ORDER BY ts ASC LIMIT ?)",
                (extra,),
            )
        cutoff = time.time() - stats_keep_hours * 3600
        self.execute("DELETE FROM stats_ts WHERE ts < ?", (cutoff,))
        self.execute("DELETE FROM packet_payloads WHERE packet_id NOT IN (SELECT id FROM packets)")

    def wipe_telemetry(self) -> None:
        with self._lock:
            for table in ("packet_payloads", "packets", "flows", "alerts", "stats_ts", "hosts"):
                self._conn.execute(f"DELETE FROM {table}")
            try:
                self._conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('packets','flows','alerts')")
            except sqlite3.OperationalError:
                pass

    def db_size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0


def serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in ("ts", "start_ts", "end_ts", "first_seen", "last_seen", "started_at"):
        if key in out and out[key] is not None:
            out[f"{key}_iso"] = iso(out[key])
    if "extra" in out and isinstance(out["extra"], str):
        try:
            out["extra"] = json.loads(out["extra"])
        except json.JSONDecodeError:
            pass
    return out
