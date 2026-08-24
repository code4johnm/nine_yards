"""REST + WebSocket API for the SOC dashboard."""

from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, File, Header, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import demo as demo_mod
from .config import Settings
from .db import Store, serialize_row
from .detect import scan_like_sql_hint
from .engine import Engine
from .util import SEVERITY_ORDER, flags_str, iface_stats, iso, list_ifaces, parse_range, tool_versions, zscore

BPF_PRESETS = [
    {"id": "all", "label": "All traffic", "bpf": ""},
    {"id": "ip", "label": "IPv4 only", "bpf": "ip"},
    {"id": "tcp", "label": "TCP", "bpf": "tcp"},
    {"id": "udp", "label": "UDP", "bpf": "udp"},
    {"id": "icmp", "label": "ICMP", "bpf": "icmp"},
    {"id": "dns", "label": "DNS (53)", "bpf": "port 53"},
    {"id": "web", "label": "HTTP/HTTPS", "bpf": "tcp port 80 or tcp port 443"},
    {"id": "ssh", "label": "SSH (22)", "bpf": "tcp port 22"},
    {"id": "not-arp", "label": "Not ARP", "bpf": "not arp"},
    {"id": "custom", "label": "Custom…", "bpf": None},
]
from .version import APP_NAME, VERSION

WEB = Path(__file__).resolve().parent.parent / "web"


def _auth(settings: Settings, authorization: str | None, x_token: str | None) -> None:
    if not settings.api_token:
        return
    offered = x_token or ""
    if authorization and authorization.lower().startswith("bearer "):
        offered = authorization.split(" ", 1)[1]
    if offered != settings.api_token:
        raise HTTPException(401, "invalid token")


def _window(range_: str | None, ts_from: float | None, ts_to: float | None) -> tuple[float, float]:
    return parse_range(range_, ts_from, ts_to)


def build_app(settings: Settings, store: Store, engine: Engine, lifespan=None) -> FastAPI:
    app = FastAPI(title=APP_NAME, version=VERSION, lifespan=lifespan)
    api = APIRouter(prefix="/api")

    @app.middleware("http")
    async def token_mw(request, call_next):
        if request.url.path.startswith("/api") and settings.api_token:
            if request.url.path == "/api/health":
                return await call_next(request)
            auth = request.headers.get("authorization")
            tok = request.headers.get("x-nids-token")
            try:
                _auth(settings, auth, tok)
            except HTTPException as e:
                return JSONResponse({"detail": e.detail}, status_code=e.status_code)
        return await call_next(request)

    @api.get("/health")
    def health() -> dict[str, Any]:
        tools = tool_versions()
        sensor = store.get_sensor()
        cap = engine.capture.status()
        return {
            "ok": True,
            "app": APP_NAME,
            "version": VERSION,
            "bind": f"{settings.host}:{settings.port}",
            "uptime_s": time.time() - engine.started_at,
            "db_bytes": store.db_size(),
            "packets": store.scalar("SELECT COUNT(*) FROM packets"),
            "flows": store.scalar("SELECT COUNT(*) FROM flows"),
            "alerts": store.scalar("SELECT COUNT(*) FROM alerts"),
            "demo_loaded": bool(store.get_kv("demo_loaded")),
            "sensor": sensor,
            "capture": cap,
            "tools": tools,
            "payload_enabled": settings.payload_enabled,
            "live_enabled": settings.live_enabled,
            "iface": settings.iface,
            "iface_stats": iface_stats(settings.iface),
            "geoip": _geo_status(),
        }

    @api.get("/kpis")
    def kpis(range: str = "15m", ts_from: float | None = None, ts_to: float | None = None) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        k = engine.kpis(t0, t1)
        k["range"] = {"from": t0, "to": t1, "from_iso": iso(t0), "to_iso": iso(t1)}
        k["demo"] = bool(store.get_kv("demo_loaded"))
        k["demo_label"] = store.get_kv("demo_label")
        return k

    @api.get("/timeseries")
    def timeseries(
        metric: str = "pps",
        range: str = "15m",
        ts_from: float | None = None,
        ts_to: float | None = None,
    ) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        col = {
            "pps": "pps",
            "bps": "bps",
            "flows": "flows_new",
            "flows_active": "flows_active",
            "alerts": "alert_rate",
            "drops": "drops",
        }.get(metric, "pps")
        rows = store.query(
            f"SELECT ts, {col} AS v FROM stats_ts WHERE ts BETWEEN ? AND ? ORDER BY ts",
            (t0, t1),
        )
        if not rows and metric in ("pps", "bps", "alerts"):
            rows = _packet_buckets(store, t0, t1, metric)
        values = [r["v"] or 0 for r in rows]
        hist = values[:-1] if len(values) > 4 else values
        current = values[-1] if values else 0
        return {
            "metric": metric,
            "points": [{"t": r["ts"], "t_iso": iso(r["ts"]), "v": r["v"] or 0} for r in rows],
            "zscore": zscore(float(current or 0), [float(x or 0) for x in hist]),
        }

    @api.get("/packets")
    def packets(
        range: str = "15m",
        ts_from: float | None = None,
        ts_to: float | None = None,
        q: str | None = None,
        ip: str | None = None,
        port: int | None = None,
        proto: str | None = None,
        flow_id: int | None = None,
        l7: str | None = None,
        retrans: bool = False,
        vlan_only: bool = False,
        limit: int = 200,
        offset: int = 0,
        sort: str = "ts",
        dir: str = "desc",
    ) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        where = ["ts BETWEEN ? AND ?"]
        args: list[Any] = [t0, t1]
        if flow_id:
            where = ["flow_id = ?"]
            args = [flow_id]
        if ip:
            where.append("(src_ip = ? OR dst_ip = ?)")
            args.extend([ip, ip])
        if port:
            where.append("(src_port = ? OR dst_port = ?)")
            args.extend([port, port])
        if proto:
            where.append("UPPER(proto) = UPPER(?)")
            args.append(proto)
        if l7:
            where.append("l7 = ?")
            args.append(l7)
        if retrans:
            where.append("is_retrans = 1")
        if vlan_only:
            where.append("vlan IS NOT NULL")
        if q:
            where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR IFNULL(info,'') LIKE ? OR IFNULL(sni,'') LIKE ? OR IFNULL(l7,'') LIKE ?)")
            like = f"%{q}%"
            args.extend([like, like, like, like, like])
        sort_col = sort if sort in {"ts", "length", "src_ip", "dst_ip", "proto", "src_port", "dst_port"} else "ts"
        order = "ASC" if dir.lower() == "asc" else "DESC"
        limit = min(max(limit, 1), 2000)
        sql = f"SELECT * FROM packets WHERE {' AND '.join(where)} ORDER BY {sort_col} {order} LIMIT ? OFFSET ?"
        rows = store.query(sql, args + [limit, offset])
        total = store.scalar(f"SELECT COUNT(*) FROM packets WHERE {' AND '.join(where)}", args)
        out = []
        for r in rows:
            r = serialize_row(r)
            r["tcp_flags_s"] = flags_str(r.get("tcp_flags"))
            out.append(r)
        return {"rows": out, "total": total, "limit": limit, "offset": offset}

    @api.get("/packets/{pid}")
    def packet_one(pid: int) -> dict[str, Any]:
        r = store.query_one("SELECT * FROM packets WHERE id=?", (pid,))
        if not r:
            raise HTTPException(404, "packet not found")
        r = serialize_row(r)
        r["tcp_flags_s"] = flags_str(r.get("tcp_flags"))
        return r

    @api.get("/packets/{pid}/payload")
    def packet_payload(pid: int) -> dict[str, Any]:
        if not settings.payload_enabled:
            raise HTTPException(403, "payload storage disabled (enable NIDS_STORE_PAYLOAD=1)")
        pkt = store.query_one("SELECT id, payload_len FROM packets WHERE id=?", (pid,))
        if not pkt:
            raise HTTPException(404, "packet not found")
        body = store.query_one("SELECT hex, ascii FROM packet_payloads WHERE packet_id=?", (pid,))
        return {
            "packet_id": pid,
            "payload_len": pkt["payload_len"],
            "hex": (body or {}).get("hex"),
            "ascii": (body or {}).get("ascii"),
            "capped": settings.payload_max_bytes,
        }

    @api.get("/flows")
    def flows(
        range: str = "15m",
        ts_from: float | None = None,
        ts_to: float | None = None,
        q: str | None = None,
        ip: str | None = None,
        proto: str | None = None,
        view: str | None = None,
        limit: int = 200,
        offset: int = 0,
        sort: str = "bytes",
        dir: str = "desc",
    ) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        where = ["start_ts <= ? AND end_ts >= ?"]
        args: list[Any] = [t1, t0]
        if ip:
            where.append("(src_ip=? OR dst_ip=?)")
            args.extend([ip, ip])
        if proto:
            where.append("UPPER(proto)=UPPER(?)")
            args.append(proto)
        if q:
            where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR IFNULL(l7,'') LIKE ? OR IFNULL(sni,'') LIKE ?)")
            like = f"%{q}%"
            args.extend([like, like, like, like])
        if view == "elephant":
            where.append("(bytes+bytes_rev) >= 100000")
        elif view == "scan":
            where.append(scan_like_sql_hint())
        elif view == "long":
            where.append("duration >= 30")
        elif view == "short":
            where.append("duration IS NOT NULL AND duration < 2")
        sort_map = {
            "bytes": "(bytes+bytes_rev)",
            "packets": "(packets+packets_rev)",
            "duration": "duration",
            "start_ts": "start_ts",
            "end_ts": "end_ts",
        }
        sort_col = sort_map.get(sort, "(bytes+bytes_rev)")
        order = "ASC" if dir.lower() == "asc" else "DESC"
        limit = min(max(limit, 1), 2000)
        w = " AND ".join(where)
        rows = store.query(
            f"SELECT * FROM flows WHERE {w} ORDER BY {sort_col} {order} LIMIT ? OFFSET ?",
            args + [limit, offset],
        )
        total = store.scalar(f"SELECT COUNT(*) FROM flows WHERE {w}", args)
        out = []
        for r in rows:
            r = serialize_row(r)
            r["tcp_flags_s"] = flags_str(r.get("tcp_flags"))
            r["total_bytes"] = (r.get("bytes") or 0) + (r.get("bytes_rev") or 0)
            r["total_packets"] = (r.get("packets") or 0) + (r.get("packets_rev") or 0)
            out.append(r)
        return {"rows": out, "total": total, "limit": limit, "offset": offset}

    @api.get("/flows/{fid}")
    def flow_one(fid: int) -> dict[str, Any]:
        r = store.query_one("SELECT * FROM flows WHERE id=?", (fid,))
        if not r:
            raise HTTPException(404, "flow not found")
        r = serialize_row(r)
        r["tcp_flags_s"] = flags_str(r.get("tcp_flags"))
        r["total_bytes"] = (r.get("bytes") or 0) + (r.get("bytes_rev") or 0)
        r["total_packets"] = (r.get("packets") or 0) + (r.get("packets_rev") or 0)
        return r

    @api.get("/alerts")
    def alerts(
        range: str = "15m",
        ts_from: float | None = None,
        ts_to: float | None = None,
        q: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        ip: str | None = None,
        include_acked: bool = False,
        include_muted: bool = False,
        hide_demo: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        where = ["last_seen BETWEEN ? AND ?"]
        args: list[Any] = [t0, t1]
        if not include_acked:
            where.append("acked=0")
        if not include_muted:
            where.append("muted=0")
        if hide_demo:
            where.append("is_demo=0")
        if severity:
            sevs = [s.strip().lower() for s in severity.split(",") if s.strip()]
            sevs = [s for s in sevs if s in SEVERITY_ORDER]
            if sevs:
                where.append(f"severity IN ({','.join('?' for _ in sevs)})")
                args.extend(sevs)
        if source:
            where.append("source=?")
            args.append(source)
        if ip:
            where.append("(src_ip=? OR dst_ip=?)")
            args.extend([ip, ip])
        if q:
            where.append("(signature LIKE ? OR sid LIKE ? OR IFNULL(category,'') LIKE ?)")
            like = f"%{q}%"
            args.extend([like, like, like])
        w = " AND ".join(where)
        rows = [serialize_row(r) for r in store.query(
            f"SELECT * FROM alerts WHERE {w} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            args + [min(limit, 2000), offset],
        )]
        total = store.scalar(f"SELECT COUNT(*) FROM alerts WHERE {w}", args)
        demo_n = store.scalar(f"SELECT COUNT(*) FROM alerts WHERE {w} AND is_demo=1", args)
        return {"rows": rows, "total": total, "demo": demo_n, "limit": limit, "offset": offset}

    @api.post("/alerts/{aid}/ack")
    def alert_ack(aid: int, body: dict | None = None) -> dict[str, Any]:
        row = store.query_one("SELECT id FROM alerts WHERE id=?", (aid,))
        if not row:
            raise HTTPException(404, "alert not found")
        store.execute("UPDATE alerts SET acked=1 WHERE id=?", (aid,))
        return {"ok": True, "id": aid, "acked": True}

    @api.post("/alerts/{aid}/mute")
    def alert_mute(aid: int) -> dict[str, Any]:
        row = store.query_one("SELECT id FROM alerts WHERE id=?", (aid,))
        if not row:
            raise HTTPException(404, "alert not found")
        store.execute("UPDATE alerts SET muted=1 WHERE id=?", (aid,))
        return {"ok": True, "id": aid, "muted": True}

    @api.post("/alerts/{aid}/comment")
    def alert_comment(aid: int, body: dict) -> dict[str, Any]:
        row = store.query_one("SELECT id FROM alerts WHERE id=?", (aid,))
        if not row:
            raise HTTPException(404, "alert not found")
        store.execute("UPDATE alerts SET comment=? WHERE id=?", (body.get("comment", ""), aid))
        return {"ok": True, "id": aid}

    @api.get("/stats/overview")
    def stats_overview(range: str = "15m", ts_from: float | None = None, ts_to: float | None = None) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        proto = store.query(
            """SELECT COALESCE(l7, proto) AS name, COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes
               FROM packets WHERE ts BETWEEN ? AND ? GROUP BY name ORDER BY packets DESC LIMIT 20""",
            (t0, t1),
        )
        flags = store.query(
            """SELECT tcp_flags AS flags, COUNT(*) AS n FROM packets
               WHERE ts BETWEEN ? AND ? AND proto='TCP' AND tcp_flags IS NOT NULL
               GROUP BY tcp_flags ORDER BY n DESC LIMIT 20""",
            (t0, t1),
        )
        for f in flags:
            f["name"] = flags_str(f["flags"]) or str(f["flags"])
        sizes = _size_hist(store, t0, t1)
        ports = store.query(
            """SELECT dst_port AS port, proto, COUNT(*) AS n, COALESCE(SUM(length),0) AS bytes
               FROM packets WHERE ts BETWEEN ? AND ? AND dst_port IS NOT NULL
               GROUP BY dst_port, proto ORDER BY n DESC LIMIT 30""",
            (t0, t1),
        )
        talkers = store.query(
            """SELECT src_ip AS ip, COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes
               FROM packets WHERE ts BETWEEN ? AND ? AND src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY bytes DESC LIMIT 15""",
            (t0, t1),
        )
        dests = store.query(
            """SELECT dst_ip AS ip, COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes
               FROM packets WHERE ts BETWEEN ? AND ? AND dst_ip IS NOT NULL
               GROUP BY dst_ip ORDER BY bytes DESC LIMIT 15""",
            (t0, t1),
        )
        apps = store.query(
            """SELECT COALESCE(l7,'other') AS app, COUNT(*) AS packets, COALESCE(SUM(length),0) AS bytes
               FROM packets WHERE ts BETWEEN ? AND ? GROUP BY app ORDER BY bytes DESC LIMIT 15""",
            (t0, t1),
        )
        sigs = store.query(
            """SELECT signature, severity, COUNT(*) AS n, SUM(count) AS hits
               FROM alerts WHERE last_seen BETWEEN ? AND ? AND muted=0
               GROUP BY signature, severity ORDER BY hits DESC LIMIT 15""",
            (t0, t1),
        )
        attackers = store.query(
            """SELECT src_ip AS ip, COUNT(*) AS n FROM alerts
               WHERE last_seen BETWEEN ? AND ? AND muted=0 AND src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY n DESC LIMIT 10""",
            (t0, t1),
        )
        victims = store.query(
            """SELECT dst_ip AS ip, COUNT(*) AS n FROM alerts
               WHERE last_seen BETWEEN ? AND ? AND muted=0 AND dst_ip IS NOT NULL
               GROUP BY dst_ip ORDER BY n DESC LIMIT 10""",
            (t0, t1),
        )
        inbound = store.query_one(
            """SELECT COALESCE(SUM(bytes_rev),0) AS inbound, COALESCE(SUM(bytes),0) AS outbound
               FROM flows WHERE start_ts <= ? AND end_ts >= ?""",
            (t1, t0),
        ) or {"inbound": 0, "outbound": 0}
        iat = _interarrival(store, t0, t1)
        return {
            "protocols": proto,
            "tcp_flags": flags,
            "sizes": sizes,
            "ports": ports,
            "talkers": talkers,
            "destinations": dests,
            "apps": apps,
            "top_signatures": sigs,
            "top_alert_src": attackers,
            "top_alert_dst": victims,
            "direction": inbound,
            "interarrival": iat,
        }

    @api.get("/hosts")
    def hosts(
        range: str = "15m",
        ts_from: float | None = None,
        ts_to: float | None = None,
        q: str | None = None,
        limit: int = 200,
        offset: int = 0,
        sort: str = "bytes_out",
    ) -> dict[str, Any]:
        t0, t1 = _window(range, ts_from, ts_to)
        where = ["last_seen BETWEEN ? AND ?"]
        args: list[Any] = [t0, t1]
        if q:
            where.append("ip LIKE ?")
            args.append(f"%{q}%")
        sort_col = sort if sort in {"bytes_in", "bytes_out", "packets_in", "packets_out", "alert_count", "last_seen"} else "bytes_out"
        w = " AND ".join(where)
        rows = [serialize_row(r) for r in store.query(
            f"SELECT * FROM hosts WHERE {w} ORDER BY {sort_col} DESC LIMIT ? OFFSET ?",
            args + [min(limit, 2000), offset],
        )]
        total = store.scalar(f"SELECT COUNT(*) FROM hosts WHERE {w}", args)
        return {"rows": rows, "total": total}

    @api.get("/hosts/{ip}")
    def host_one(ip: str, range: str = "1h") -> dict[str, Any]:
        row = store.query_one("SELECT * FROM hosts WHERE ip=?", (ip,))
        if not row:
            raise HTTPException(404, "host not found")
        t0, t1 = _window(range, None, None)
        conv = store.query(
            """SELECT src_ip, dst_ip, src_port, dst_port, proto, SUM(packets+packets_rev) AS packets,
                      SUM(bytes+bytes_rev) AS bytes, MIN(start_ts) AS start_ts, MAX(end_ts) AS end_ts
               FROM flows WHERE (src_ip=? OR dst_ip=?) AND start_ts<=? AND end_ts>=?
               GROUP BY src_ip, dst_ip, src_port, dst_port, proto
               ORDER BY bytes DESC LIMIT 40""",
            (ip, ip, t1, t0),
        )
        alerts = [serialize_row(a) for a in store.query(
            "SELECT * FROM alerts WHERE (src_ip=? OR dst_ip=?) ORDER BY last_seen DESC LIMIT 20",
            (ip, ip),
        )]
        return {"host": serialize_row(row), "conversations": conv, "alerts": alerts}

    @api.get("/sensor")
    def sensor() -> dict[str, Any]:
        s = store.get_sensor()
        s["capture"] = engine.capture.status()
        s["ifaces"] = list_ifaces()
        s["settings"] = {
            "iface": settings.iface,
            "bpf": settings.bpf,
            "payload_enabled": settings.payload_enabled,
            "store_pcap": settings.store_pcap,
            "bind": f"{settings.host}:{settings.port}",
            "suricata_eve": settings.suricata_eve,
            "zeek_dir": settings.zeek_dir,
        }
        return s

    @api.get("/meta")
    def meta() -> dict[str, Any]:
        t0, t1 = parse_range("24h")
        protos = [r["proto"] for r in store.query(
            "SELECT DISTINCT proto FROM packets WHERE proto IS NOT NULL ORDER BY proto"
        )]
        l7s = [r["l7"] for r in store.query(
            "SELECT DISTINCT l7 FROM packets WHERE l7 IS NOT NULL AND l7 != '' ORDER BY l7"
        )]
        sources = [r["source"] for r in store.query(
            "SELECT DISTINCT source FROM alerts WHERE source IS NOT NULL ORDER BY source"
        )]
        return {
            "ifaces": list_ifaces(),
            "bpf_presets": BPF_PRESETS,
            "severities": list(SEVERITY_ORDER),
            "protocols": protos or ["TCP", "UDP", "ICMP", "ARP"],
            "l7": l7s,
            "alert_sources": sources,
            "settings": {
                "iface": settings.iface,
                "bpf": settings.bpf,
                "payload_enabled": settings.payload_enabled,
                "payload_max_bytes": settings.payload_max_bytes,
                "store_pcap": settings.store_pcap,
                "autoload_demo": settings.autoload_demo,
                "live_enabled": settings.live_enabled,
            },
            "capture": engine.capture.status(),
            "range": {"from": t0, "to": t1},
        }

    @api.post("/sensor/start")
    def sensor_start(body: dict | None = None) -> dict[str, Any]:
        body = body or {}
        try:
            st = engine.start_live(
                body.get("iface"),
                body.get("bpf"),
                store_pcap=body.get("store_pcap"),
            )
            engine.apply_settings({
                "iface": engine.settings.iface,
                "bpf": engine.settings.bpf,
                "store_pcap": engine.settings.store_pcap,
            })
            return {"ok": True, **st}
        except Exception as e:
            raise HTTPException(400, f"capture failed: {e}") from e

    @api.post("/sensor/stop")
    def sensor_stop() -> dict[str, Any]:
        return {"ok": True, **engine.stop_live()}

    @api.post("/demo/load")
    def demo_load() -> dict[str, Any]:
        stats = demo_mod.load_demo(store, payload=settings.payload_enabled)
        return {"ok": True, "demo": True, **stats}

    @api.post("/pcap/load")
    async def pcap_load(file: UploadFile = File(...), replace: bool = True) -> dict[str, Any]:
        dest = settings.capture_dir / "upload.pcap"
        data = await file.read()
        if len(data) > 80_000_000:
            raise HTTPException(413, "pcap too large (80MB cap)")
        dest.write_bytes(data)
        try:
            dest.chmod(0o600)
        except OSError:
            pass
        stats = engine.ingest_pcap_file(str(dest), replace=replace)
        return {"ok": True, "path": str(dest), **stats}

    @api.get("/settings")
    def get_settings() -> dict[str, Any]:
        return {
            "host": settings.host,
            "port": settings.port,
            "iface": settings.iface,
            "bpf": settings.bpf,
            "payload_enabled": settings.payload_enabled,
            "payload_max_bytes": settings.payload_max_bytes,
            "store_pcap": settings.store_pcap,
            "live_enabled": settings.live_enabled,
            "autoload_demo": settings.autoload_demo,
            "max_packets": settings.max_packets,
            "suricata_eve": settings.suricata_eve,
            "zeek_dir": settings.zeek_dir,
            "token_required": bool(settings.api_token),
            "ifaces": list_ifaces(),
            "bpf_presets": BPF_PRESETS,
        }

    @api.put("/settings")
    def put_settings(body: dict) -> dict[str, Any]:
        snap = engine.apply_settings(body or {})
        return {"ok": True, **snap}

    @api.get("/export/{kind}")
    def export(kind: str, range: str = "15m", fmt: str = "csv") -> Any:
        t0, t1 = _window(range, None, None)
        if kind == "packets":
            rows = store.query("SELECT * FROM packets WHERE ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 20000", (t0, t1))
        elif kind == "flows":
            rows = store.query("SELECT * FROM flows WHERE start_ts<=? AND end_ts>=? LIMIT 20000", (t1, t0))
        elif kind == "alerts":
            rows = store.query("SELECT * FROM alerts WHERE last_seen BETWEEN ? AND ? LIMIT 20000", (t0, t1))
        else:
            raise HTTPException(404, "unknown export")
        if fmt == "json":
            return JSONResponse(rows)
        if not rows:
            return PlainTextResponse("", media_type="text/csv")
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
        filename = f"{kind}.csv"
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.websocket("/ws/live")
    async def ws_live(ws: WebSocket) -> None:
        await ws.accept()
        try:
            while True:
                await ws.send_json({"type": "kpi", "data": engine.last_kpi or engine.kpis(*parse_range("5m"))})
                import asyncio

                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            return
        except Exception:
            try:
                await ws.close()
            except Exception:
                return

    app.include_router(api)
    if WEB.exists():
        app.mount("/", StaticFiles(directory=str(WEB), html=True), name="web")
    return app


def _geo_status() -> dict[str, Any]:
    mmdb = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
    dat = Path("/usr/share/GeoIP/GeoIP.dat")
    return {
        "enabled": False,
        "reason": "No GeoLite2 MMDB present; legacy GeoIP.dat is not used. Map stubbed.",
        "legacy_dat": dat.exists(),
        "mmdb": mmdb.exists(),
    }


def _packet_buckets(store: Store, t0: float, t1: float, metric: str) -> list[dict[str, Any]]:
    span = max(1.0, t1 - t0)
    buckets = 40
    width = span / buckets
    rows = store.query("SELECT ts, length FROM packets WHERE ts BETWEEN ? AND ?", (t0, t1))
    acc = [0.0] * buckets
    for r in rows:
        i = min(buckets - 1, int((r["ts"] - t0) / width))
        if metric == "bps":
            acc[i] += (r["length"] or 0) * 8
        else:
            acc[i] += 1
    if metric == "alerts":
        arows = store.query("SELECT ts FROM alerts WHERE ts BETWEEN ? AND ?", (t0, t1))
        acc = [0.0] * buckets
        for r in arows:
            i = min(buckets - 1, int((r["ts"] - t0) / width))
            acc[i] += 1
    out = []
    for i, v in enumerate(acc):
        ts = t0 + (i + 0.5) * width
        out.append({"ts": ts, "v": v / width})
    return out


def _size_hist(store: Store, t0: float, t1: float) -> list[dict[str, Any]]:
    bounds = [0, 64, 128, 256, 512, 1024, 1514, 9000]
    labels = ["0-64", "65-128", "129-256", "257-512", "513-1024", "1025-1514", "1515+"]
    counts = [0] * len(labels)
    rows = store.query("SELECT length FROM packets WHERE ts BETWEEN ? AND ?", (t0, t1))
    for r in rows:
        n = r["length"] or 0
        placed = False
        for i in range(len(labels) - 1):
            if n <= bounds[i + 1]:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    return [{"bucket": labels[i], "n": counts[i]} for i in range(len(labels))]


def _interarrival(store: Store, t0: float, t1: float) -> dict[str, Any]:
    rows = store.query("SELECT ts FROM packets WHERE ts BETWEEN ? AND ? ORDER BY ts LIMIT 5000", (t0, t1))
    if len(rows) < 3:
        return {"n": len(rows), "mean_ms": None, "p50_ms": None, "p95_ms": None}
    dts = [(rows[i]["ts"] - rows[i - 1]["ts"]) * 1000 for i in range(1, len(rows))]
    dts.sort()
    mean = sum(dts) / len(dts)
    p50 = dts[int(len(dts) * 0.5)]
    p95 = dts[int(len(dts) * 0.95)]
    return {"n": len(dts), "mean_ms": round(mean, 3), "p50_ms": round(p50, 3), "p95_ms": round(p95, 3)}
