"""Synthetic lab traffic + DEMO IDS events.

Traffic is RFC1918 / documentation-prefix only (TEST-NET-3 203.0.113.0/24).
All generated alerts are tagged is_demo=1 and should be treated as labeled DEMO.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from .config import load_settings
from .db import Store
from .detect import Detector
from .flows import FlowTable
from .parser import parse_frame
from .pcapio import (
    arp_request,
    dns_query,
    dns_response,
    ethernet,
    http_req,
    http_resp,
    icmp_echo,
    tcp,
    tls_client_hello,
    udp,
    PcapWriter,
)
from .util import setup_logging

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample"

MAC = {
    "ws": "02:50:01:00:00:10",
    "srv": "02:50:01:00:00:20",
    "dns": "02:50:01:00:00:30",
    "gw": "02:50:01:00:00:01",
    "scan": "02:50:01:00:00:99",
    "iot": "02:50:01:00:00:77",
    "ext": "02:00:00:00:00:50",
}

IP = {
    "ws": "10.50.1.10",
    "srv": "10.50.1.20",
    "dns": "10.50.1.30",
    "gw": "10.50.1.1",
    "scan": "10.50.1.99",
    "iot": "10.50.1.77",
    "ext_web": "203.0.113.10",
    "ext_c2": "203.0.113.50",
    "ext_dns": "203.0.113.53",
    "ntp": "203.0.113.123",
}


def _eth(src_role: str, dst_role: str, payload: bytes, vlan: int | None = None) -> bytes:
    return ethernet(MAC[src_role], MAC[dst_role], 0x0800, payload, vlan=vlan)


def _tcp_h(src_role: str, dst_role: str, sip: str, dip: str, sp: int, dp: int, seq: int, ack: int, flags: int, payload: bytes = b"", vlan: int | None = None, ttl: int = 64) -> bytes:
    return ethernet(MAC[src_role], MAC[dst_role], 0x0800, tcp(sip, dip, sp, dp, seq, ack, flags, payload, ttl=ttl), vlan=vlan)


def generate_frames(now: float | None = None, seed: int = 9) -> list[tuple[float, bytes]]:
    rng = random.Random(seed)
    # Default: pack the corpus so it ends ~now and still sits inside a 5m window.
    t0 = now if now is not None else time.time() - 240
    frames: list[tuple[float, bytes]] = []
    t = t0

    def add(dt: float, frame: bytes) -> None:
        nonlocal t
        t += dt
        frames.append((t, frame))

    # ARP
    add(0.01, arp_request(MAC["ws"], IP["ws"], IP["gw"]))

    # DNS: workstation resolves lab services
    for name, answer, dt in (
        ("www.lab.example.", IP["srv"], 0.02),
        ("ntp.lab.example.", IP["ntp"], 0.03),
        ("update.lab.example.", IP["ext_web"], 0.02),
    ):
        q = udp(IP["ws"], IP["dns"], rng.randint(40000, 50000), 53, dns_query(name))
        add(dt, ethernet(MAC["ws"], MAC["dns"], 0x0800, q))
        r = udp(IP["dns"], IP["ws"], 53, 40000, dns_response(name, answer))
        add(0.004, ethernet(MAC["dns"], MAC["ws"], 0x0800, r))

    # HTTP to internal web (with VLAN 80 on one conversation)
    seq = 1000
    add(0.01, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 51000, 80, seq, 0, 0x02, vlan=80))  # SYN
    add(0.002, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 80, 51000, 2000, seq + 1, 0x12, vlan=80))  # SYN-ACK
    add(0.001, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 51000, 80, seq + 1, 2001, 0x10, vlan=80))
    req = http_req("GET", "/health", "www.lab.example")
    add(0.004, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 51000, 80, seq + 1, 2001, 0x18, req, vlan=80))
    resp = http_resp(200, "healthy")
    add(0.006, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 80, 51000, 2001, seq + 1 + len(req), 0x18, resp, vlan=80))
    add(0.002, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 51000, 80, seq + 1 + len(req), 2001 + len(resp), 0x11, vlan=80))

    # TLS to documentation-prefix web (SNI)
    hello = tls_client_hello("update.lab.example")
    seq = 50000
    add(0.05, _tcp_h("ws", "gw", IP["ws"], IP["ext_web"], 52000, 443, seq, 0, 0x02, ttl=64))
    add(0.02, _tcp_h("gw", "ws", IP["ext_web"], IP["ws"], 443, 52000, 9000, seq + 1, 0x12, ttl=48))
    add(0.002, _tcp_h("ws", "gw", IP["ws"], IP["ext_web"], 52000, 443, seq + 1, 9001, 0x10))
    add(0.004, _tcp_h("ws", "gw", IP["ws"], IP["ext_web"], 52000, 443, seq + 1, 9001, 0x18, hello))
    # small app data records (not a payload dump of secrets)
    app = b"\x17\x03\x03\x00\x20" + b"\x42" * 32
    add(0.03, _tcp_h("gw", "ws", IP["ext_web"], IP["ws"], 443, 52000, 9001, seq + 1 + len(hello), 0x18, app, ttl=48))

    # SSH session (banner only)
    banner = b"SSH-2.0-OpenSSH_9.2 Demo\r\n"
    add(0.05, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 53000, 22, 10, 0, 0x02))
    add(0.004, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 22, 53000, 20, 11, 0x12))
    add(0.001, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 53000, 22, 11, 21, 0x10))
    add(0.003, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 22, 53000, 21, 11, 0x18, banner))

    # NTP-ish UDP
    add(0.04, ethernet(MAC["ws"], MAC["gw"], 0x0800, udp(IP["ws"], IP["ntp"], 123, 123, b"\x1b" + b"\x00" * 47)))

    # ICMP
    add(0.02, ethernet(MAC["ws"], MAC["gw"], 0x0800, icmp_echo(IP["ws"], IP["gw"], ident=7, seq=1)))

    # Background chatter: several short HTTP GETs
    for i in range(18):
        sp = 54000 + i
        seq = 8000 + i * 17
        path = f"/api/item/{i}"
        add(0.08 + rng.random() * 0.04, _tcp_h("ws", "srv", IP["ws"], IP["srv"], sp, 80, seq, 0, 0x02))
        add(0.002, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 80, sp, 1, seq + 1, 0x12))
        add(0.001, _tcp_h("ws", "srv", IP["ws"], IP["srv"], sp, 80, seq + 1, 2, 0x10))
        body = http_req("GET", path, "www.lab.example")
        add(0.003, _tcp_h("ws", "srv", IP["ws"], IP["srv"], sp, 80, seq + 1, 2, 0x18, body))
        resp = http_resp(200 if i % 7 else 404, "x" * (40 + i))
        add(0.005, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 80, sp, 2, seq + 1 + len(body), 0x18, resp))
        add(0.002, _tcp_h("ws", "srv", IP["ws"], IP["srv"], sp, 80, seq + 1 + len(body), 2 + len(resp), 0x11))

    # Elephant flow: bulk transfer on 8443
    seq = 100000
    ack = 1
    add(0.2, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 55000, 8443, seq, 0, 0x02))
    add(0.002, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 8443, 55000, 1, seq + 1, 0x12))
    add(0.001, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 55000, 8443, seq + 1, 2, 0x10))
    chunk = b"A" * 1400
    for i in range(90):
        add(0.004, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 8443, 55000, ack, seq + 1, 0x18, chunk))
        ack += 1400
        if i % 4 == 0:
            add(0.001, _tcp_h("ws", "srv", IP["ws"], IP["srv"], 55000, 8443, seq + 1, ack, 0x10))

    # Retransmission duplicate seq
    add(0.01, _tcp_h("srv", "ws", IP["srv"], IP["ws"], 8443, 55000, ack - 1400, seq + 1, 0x18, chunk))

    # Vertical scan from 10.50.1.99 against the web server
    for port in list(range(20, 45)) + [80, 443, 445, 3389, 5900, 8080, 8443]:
        sp = 40000 + port
        add(0.012, _tcp_h("scan", "srv", IP["scan"], IP["srv"], sp, port, 1, 0, 0x02, ttl=44))
        if port in (80, 443, 22, 8443):
            add(0.002, _tcp_h("srv", "scan", IP["srv"], IP["scan"], port, sp, 1, 2, 0x12))
            add(0.001, _tcp_h("scan", "srv", IP["scan"], IP["srv"], sp, port, 2, 2, 0x04))  # RST
        else:
            add(0.001, _tcp_h("srv", "scan", IP["srv"], IP["scan"], port, sp, 1, 2, 0x14))  # RST-ACK

    # Horizontal scan: SYN to many hosts on 22
    for last in range(2, 28):
        dip = f"10.50.1.{last}"
        add(0.008, ethernet(MAC["scan"], MAC["gw"], 0x0800, tcp(IP["scan"], dip, 41000 + last, 22, 1, 0, 0x02, ttl=44)))

    # SYN burst toward the gateway
    for i in range(90):
        add(0.004, _tcp_h("scan", "gw", IP["scan"], IP["gw"], 42000 + i, 80, 1, 0, 0x02, ttl=40))

    # FIN-only and NULL probes
    add(0.02, _tcp_h("scan", "srv", IP["scan"], IP["srv"], 43001, 80, 1, 0, 0x01))
    add(0.01, _tcp_h("scan", "srv", IP["scan"], IP["srv"], 43002, 80, 1, 0, 0x00))

    # Beaconing IoT host -> documentation C2 on 443 every ~20s (fits a 5m window)
    beacon_hello = tls_client_hello("status.lab.example")
    bt = t
    for i in range(8):
        bt = t0 + 20 + i * 20
        seq = 70000 + i
        frames.append((bt, _tcp_h("iot", "gw", IP["iot"], IP["ext_c2"], 46000, 443, seq, 0, 0x02)))
        frames.append((bt + 0.04, _tcp_h("gw", "iot", IP["ext_c2"], IP["iot"], 443, 46000, 1, seq + 1, 0x12, ttl=50)))
        frames.append((bt + 0.05, _tcp_h("iot", "gw", IP["iot"], IP["ext_c2"], 46000, 443, seq + 1, 2, 0x18, beacon_hello)))
        frames.append((bt + 0.08, _tcp_h("iot", "gw", IP["iot"], IP["ext_c2"], 46000, 443, seq + 1 + len(beacon_hello), 2, 0x11)))

    # ICMP burst
    for i in range(70):
        add(0.006, ethernet(MAC["scan"], MAC["gw"], 0x0800, icmp_echo(IP["scan"], IP["gw"], ident=9, seq=i)))

    # DNS burst
    for i in range(45):
        qname = f"n{i}.bulk.lab.example."
        add(0.01, ethernet(MAC["scan"], MAC["dns"], 0x0800, udp(IP["scan"], IP["dns"], 53000 + i, 53, dns_query(qname))))

    frames.sort(key=lambda x: x[0])
    return frames


DEMO_ALERTS = [
    {
        "sid": "2010937",
        "signature": "ET SCAN Potential SSH Scan",
        "category": "Reconnaissance",
        "severity": "medium",
        "src_ip": IP["scan"],
        "dst_ip": IP["srv"],
        "src_port": 41022,
        "dst_port": 22,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2100366",
        "signature": "GPL POLICY Unusual Port 445 traffic",
        "category": "Policy",
        "severity": "low",
        "src_ip": IP["scan"],
        "dst_ip": IP["srv"],
        "src_port": 40445,
        "dst_port": 445,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2021997",
        "signature": "ET INFO Observed DNS Query to .example TLD",
        "category": "Misc",
        "severity": "info",
        "src_ip": IP["ws"],
        "dst_ip": IP["dns"],
        "src_port": 40000,
        "dst_port": 53,
        "proto": "UDP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2018959",
        "signature": "ET POLICY TLS possible TOR SSL traffic",
        "category": "Policy",
        "severity": "medium",
        "src_ip": IP["iot"],
        "dst_ip": IP["ext_c2"],
        "src_port": 46000,
        "dst_port": 443,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
        "comment": "DEMO: documentation-prefix destination, not a real TOR classifier.",
    },
    {
        "sid": "2800000",
        "signature": "DEMO ET WEB_SERVER 404 on /api/item",
        "category": "Web Application Attack",
        "severity": "low",
        "src_ip": IP["ws"],
        "dst_ip": IP["srv"],
        "src_port": 54000,
        "dst_port": 80,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2030500",
        "signature": "DEMO ET SCAN Nmap-like TCP SYN scan",
        "category": "Reconnaissance",
        "severity": "high",
        "src_ip": IP["scan"],
        "dst_ip": IP["srv"],
        "dst_port": 80,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2019363",
        "signature": "ET SCAN Behavioral Unusual Port 3389 traffic Internal",
        "category": "Reconnaissance",
        "severity": "medium",
        "src_ip": IP["scan"],
        "dst_ip": IP["srv"],
        "dst_port": 3389,
        "proto": "TCP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "2101413",
        "signature": "GPL ICMP_INFO PING *NIX",
        "category": "Misc",
        "severity": "info",
        "src_ip": IP["ws"],
        "dst_ip": IP["gw"],
        "proto": "ICMP",
        "source": "suricata-demo",
        "is_demo": True,
    },
    {
        "sid": "9000999",
        "signature": "DEMO STAT Possible C2 beacon to TEST-NET-3",
        "category": "C2",
        "severity": "critical",
        "src_ip": IP["iot"],
        "dst_ip": IP["ext_c2"],
        "src_port": 46000,
        "dst_port": 443,
        "proto": "TCP",
        "source": "stat-demo",
        "is_demo": True,
    },
]


def write_sample_files(frames: list[tuple[float, bytes]]) -> Path:
    SAMPLE.mkdir(parents=True, exist_ok=True)
    pcap_path = SAMPLE / "lab-demo.pcap"
    with PcapWriter(pcap_path) as w:
        for ts, frame in frames:
            w.write(ts, frame)

    eve_path = SAMPLE / "eve.json"
    with eve_path.open("w") as f:
        for i, a in enumerate(DEMO_ALERTS):
            ts = frames[min(i * 10, len(frames) - 1)][0]
            rec = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(ts)),
                "event_type": "alert",
                "src_ip": a.get("src_ip"),
                "dest_ip": a.get("dst_ip"),
                "src_port": a.get("src_port"),
                "dest_port": a.get("dst_port"),
                "proto": a.get("proto"),
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": int(str(a["sid"])[-7:]) if str(a["sid"]).isdigit() else i,
                    "rev": 1,
                    "signature": a["signature"],
                    "category": a["category"],
                    "severity": {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3}.get(a["severity"], 3),
                },
                "demo": True,
            }
            f.write(json.dumps(rec) + "\n")

    zeek = SAMPLE / "zeek"
    zeek.mkdir(exist_ok=True)
    conn = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes",
        f"{frames[10][0]}\tC1\t{IP['ws']}\t51000\t{IP['srv']}\t80\ttcp\thttp\t0.02\t200\t180\tSF\tT\tT\t0\tShADadfF\t6\t480\t5\t400",
        f"{frames[20][0]}\tC2\t{IP['ws']}\t52000\t{IP['ext_web']}\t443\ttcp\tssl\t0.08\t400\t200\tS1\tT\tF\t0\tShADad\t4\t520\t3\t280",
        f"{frames[30][0]}\tC3\t{IP['scan']}\t40022\t{IP['srv']}\t22\ttcp\tssh\t0.01\t60\t60\tREJ\tT\tT\t0\tSr\t2\t120\t1\t60",
        f"{frames[40][0]}\tC4\t{IP['iot']}\t46000\t{IP['ext_c2']}\t443\ttcp\tssl\t0.1\t300\t80\tS1\tT\tF\t0\tShADad\t3\t380\t2\t140",
    ]
    (zeek / "conn.log").write_text("\n".join(conn) + "\n")
    dns = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqclass_name\tqtype_name\trcode_name",
        f"{frames[2][0]}\tD1\t{IP['ws']}\t40000\t{IP['dns']}\t53\tudp\twww.lab.example\tC_INTERNET\tA\tNOERROR",
        f"{frames[4][0]}\tD2\t{IP['ws']}\t40001\t{IP['dns']}\t53\tudp\tntp.lab.example\tC_INTERNET\tA\tNOERROR",
    ]
    (zeek / "dns.log").write_text("\n".join(dns) + "\n")
    http = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code",
        f"{frames[12][0]}\tH1\t{IP['ws']}\t51000\t{IP['srv']}\t80\tGET\twww.lab.example\t/health\t200",
        f"{frames[50][0]}\tH2\t{IP['ws']}\t54000\t{IP['srv']}\t80\tGET\twww.lab.example\t/api/item/0\t404",
    ]
    (zeek / "http.log").write_text("\n".join(http) + "\n")
    ssl = [
        "#separator \\x09",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tserver_name\tja3",
        f"{frames[22][0]}\tS1\t{IP['ws']}\t52000\t{IP['ext_web']}\t443\tTLSv12\tupdate.lab.example\tdemoja3aaaaaaaaaaaaaaaaaaaaaaaaaa",
        f"{frames[40][0]}\tS2\t{IP['iot']}\t46000\t{IP['ext_c2']}\t443\tTLSv12\tstatus.lab.example\tdemoja3bbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    (zeek / "ssl.log").write_text("\n".join(ssl) + "\n")
    return pcap_path


def ingest_frames(store: Store, frames: list[tuple[float, bytes]], payload: bool = False) -> dict[str, int]:
    table = FlowTable(idle_sec=30, max_sec=900)
    det = Detector()
    count = 0
    first_ts = frames[0][0] if frames else time.time()
    last_ts = first_ts
    bytes_total = 0
    batch = []
    for ts, frame in frames:
        pkt = parse_frame(ts, frame, store_payload=payload)
        if not pkt:
            continue
        fl = table.update(pkt)
        if fl.db_id is None:
            fl.db_id = store.upsert_flow(fl.to_row(closed=0))
        else:
            store.upsert_flow(fl.to_row(closed=0))
        pkt["flow_id"] = fl.db_id
        batch.append(pkt)
        store.bump_host(pkt.get("src_ip"), ts, "out", pkt["length"], pkt.get("dst_port"))
        store.bump_host(pkt.get("dst_ip"), ts, "in", pkt["length"], pkt.get("src_port"))
        for a in det.on_packet(pkt):
            a["flow_id"] = fl.db_id
            store.insert_alert(a)
        count += 1
        last_ts = ts
        bytes_total += pkt["length"]
        if len(batch) >= 200:
            store.insert_packets(batch)
            batch = []
    if batch:
        store.insert_packets(batch)
    for fl in table.expire(last_ts + 120):
        store.upsert_flow(fl.to_row(closed=1))
        for a in det.on_flow(fl):
            a["flow_id"] = fl.db_id
            store.insert_alert(a)
    for fl in table.active():
        store.upsert_flow(fl.to_row(closed=0))
        for a in det.on_flow(fl):
            a["flow_id"] = fl.db_id
            store.insert_alert(a)
    for a in det.scan_windows(last_ts):
        store.insert_alert(a)

    # timeseries buckets ~2s
    span = max(1.0, last_ts - first_ts)
    buckets = max(20, int(span / 2))
    width = span / buckets
    # precompute packet counts per bucket
    counts = [0] * buckets
    bsum = [0] * buckets
    for ts, frame in frames:
        i = min(buckets - 1, int((ts - first_ts) / width))
        counts[i] += 1
        bsum[i] += len(frame)
    for i in range(buckets):
        ts = first_ts + (i + 1) * width
        store.insert_stats(
            {
                "ts": ts,
                "pps": counts[i] / width,
                "bps": (bsum[i] * 8) / width,
                "flows_active": store.scalar("SELECT COUNT(*) FROM flows WHERE start_ts<=? AND end_ts>=?", (ts, ts - 5)),
                "flows_new": counts[i] // 3,
                "alert_rate": 0,
                "unique_hosts": store.scalar("SELECT COUNT(*) FROM hosts"),
                "drops": 0,
                "errors": 0,
                "packets_total": sum(counts[: i + 1]),
                "bytes_total": sum(bsum[: i + 1]),
            }
        )
    # overlay demo signature alerts near matching packets
    for a in DEMO_ALERTS:
        rec = dict(a)
        rec["ts"] = last_ts - rng_offset(a["sid"])
        rec["first_seen"] = rec["ts"]
        rec["last_seen"] = rec["ts"]
        rec["is_demo"] = True
        store.insert_alert(rec)
    store.set_kv("demo_loaded", True)
    store.set_kv("demo_label", "DEMO dataset — not live sensor traffic")
    store.set_sensor(status="idle", source="demo", iface="demo", last_error=None, packets=count, drops=0)
    return {"packets": count, "flows": store.scalar("SELECT COUNT(*) FROM flows"), "alerts": store.scalar("SELECT COUNT(*) FROM alerts")}


def rng_offset(sid: str) -> float:
    return (sum(ord(c) for c in str(sid)) % 300) + 5


def load_demo(store: Store, payload: bool = False) -> dict[str, int]:
    frames = generate_frames()
    write_sample_files(frames)
    store.wipe_telemetry()
    return ingest_frames(store, frames, payload=payload)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate and load 9yards demo telemetry")
    ap.add_argument("--ensure", action="store_true", help="Load demo only if the database is empty")
    ap.add_argument("--force", action="store_true", help="Replace existing telemetry with demo data")
    args = ap.parse_args()
    settings = load_settings()
    log = setup_logging(settings.log_path)
    store = Store(settings.db_path)
    n = store.scalar("SELECT COUNT(*) FROM packets")
    if args.ensure and n and not args.force:
        log.info("demo already present (%s packets)", n)
        return
    stats = load_demo(store, payload=settings.payload_enabled)
    log.info("demo loaded: %s", stats)
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
