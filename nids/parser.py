"""Packet metadata extraction from Ethernet frames. Payload is never stored unless enabled."""

from __future__ import annotations

import struct
from typing import Any

from .pcapio import extract_sni, ja3_from_client_hello
from .util import PROTO_IP, app_from_ports, clean_hostname, flags_str

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ipv4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _ipv6(b: bytes) -> str:
    parts = [f"{b[i]<<8 | b[i+1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _ascii_preview(data: bytes, n: int) -> str:
    chars = []
    for x in data[:n]:
        chars.append(chr(x) if 32 <= x < 127 else ".")
    return "".join(chars)


def _parse_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    pos = offset
    guard = 0
    while guard < 20 and pos < len(payload):
        guard += 1
        ln = payload[pos]
        if ln == 0:
            if not jumped:
                pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(payload):
                break
            ptr = ((ln & 0x3F) << 8) | payload[pos + 1]
            if not jumped:
                pos += 2
            jumped = True
            pos = ptr
            continue
        pos += 1
        labels.append(payload[pos : pos + ln].decode("utf-8", "replace"))
        pos += ln
    return ".".join(labels), pos


def _dns_qname(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    name, _ = _parse_dns_name(payload, 12)
    return name or None


def _dns_answers(payload: bytes) -> list[tuple[str, str]]:
    """Return (ip, owner-name) pairs from DNS A/AAAA answers."""
    if len(payload) < 12:
        return []
    qd = struct.unpack("!H", payload[4:6])[0]
    an = struct.unpack("!H", payload[6:8])[0]
    if an <= 0:
        return []
    pos = 12
    for _ in range(qd):
        _, pos = _parse_dns_name(payload, pos)
        pos += 4
        if pos > len(payload):
            return []
    out: list[tuple[str, str]] = []
    for _ in range(min(an, 24)):
        name, pos = _parse_dns_name(payload, pos)
        if pos + 10 > len(payload):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[pos : pos + 10])
        pos += 10
        if pos + rdlen > len(payload):
            break
        rdata = payload[pos : pos + rdlen]
        pos += rdlen
        host = clean_hostname(name)
        if not host:
            continue
        if rtype == 1 and rdlen == 4:
            out.append((_ipv4(rdata), host))
        elif rtype == 28 and rdlen == 16:
            out.append((_ipv6(rdata), host))
    return out


def _http_host(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    except Exception:
        return None
    for line in text.split("\r\n")[1:12]:
        if line.lower().startswith("host:"):
            return clean_hostname(line.split(":", 1)[1])
    return None


def _http_meta(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        text = payload.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace")
    except Exception:
        return None
    first = text.split("\r\n", 1)[0]
    if not (first.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "HTTP/"))):
        return None
    host = ""
    for line in text.split("\r\n")[1:6]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return (first[:80] + (f" host={host}" if host else ""))[:160]


def parse_frame(
    ts: float,
    frame: bytes,
    store_payload: bool = False,
    payload_max: int = 256,
) -> dict[str, Any] | None:
    if len(frame) < 14:
        return None
    dst_mac = _mac(frame[0:6])
    src_mac = _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    vlan = None
    if ethertype in (ETH_VLAN, ETH_QINQ) and len(frame) >= 18:
        vlan = struct.unpack("!H", frame[14:16])[0] & 0x0FFF
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18

    rec: dict[str, Any] = {
        "ts": ts,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "vlan": vlan,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "proto": "OTHER",
        "ip_proto": None,
        "length": len(frame),
        "tcp_flags": None,
        "ttl": None,
        "l7": None,
        "is_retrans": 0,
        "payload_len": 0,
        "info": None,
        "ja3": None,
        "sni": None,
        "http_host": None,
        "dns_answers": [],
        "payload": b"",
        "tcp_seq": None,
        "tcp_ack": None,
    }

    l4 = b""
    if ethertype == ETH_ARP and len(frame) >= off + 28:
        rec["proto"] = "ARP"
        op = struct.unpack("!H", frame[off + 6 : off + 8])[0]
        rec["src_ip"] = _ipv4(frame[off + 14 : off + 18])
        rec["dst_ip"] = _ipv4(frame[off + 24 : off + 28])
        rec["info"] = "request" if op == 1 else "reply"
        rec["l7"] = "arp"
        return rec

    if ethertype == ETH_IPV4 and len(frame) >= off + 20:
        iph = frame[off:]
        ver_ihl = iph[0]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(iph) < ihl:
            rec["proto"] = "IPv4"
            return rec
        total = struct.unpack("!H", iph[2:4])[0]
        rec["ttl"] = iph[8]
        rec["ip_proto"] = iph[9]
        rec["src_ip"] = _ipv4(iph[12:16])
        rec["dst_ip"] = _ipv4(iph[16:20])
        l4 = iph[ihl : max(ihl, total)]
        rec["proto"] = PROTO_IP.get(rec["ip_proto"], f"IP-{rec['ip_proto']}")
    elif ethertype == ETH_IPV6 and len(frame) >= off + 40:
        iph = frame[off:]
        rec["ip_proto"] = iph[6]
        rec["ttl"] = iph[7]
        rec["src_ip"] = _ipv6(iph[8:24])
        rec["dst_ip"] = _ipv6(iph[24:40])
        l4 = iph[40:]
        rec["proto"] = PROTO_IP.get(rec["ip_proto"], f"IPv6-{rec['ip_proto']}")
    else:
        rec["proto"] = f"ETH-{ethertype:#x}"
        return rec

    proto_num = rec["ip_proto"]
    payload = b""
    if proto_num == 6 and len(l4) >= 20:  # TCP
        rec["src_port"] = struct.unpack("!H", l4[0:2])[0]
        rec["dst_port"] = struct.unpack("!H", l4[2:4])[0]
        rec["tcp_seq"] = struct.unpack("!I", l4[4:8])[0]
        rec["tcp_ack"] = struct.unpack("!I", l4[8:12])[0]
        data_off = (l4[12] >> 4) * 4
        rec["tcp_flags"] = l4[13]
        rec["proto"] = "TCP"
        payload = l4[data_off:] if data_off <= len(l4) else b""
        rec["l7"] = app_from_ports(rec["src_port"], rec["dst_port"], "TCP")
        rec["info"] = flags_str(rec["tcp_flags"])
        if rec["l7"] in ("http", "http-alt") or (payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"HTTP")):
            meta = _http_meta(payload)
            if meta:
                rec["l7"] = "http"
                rec["info"] = meta
            rec["http_host"] = _http_host(payload)
        if rec["l7"] in ("https", "https-alt") or (payload[:1] == b"\x16"):
            sni = extract_sni(payload)
            ja3 = ja3_from_client_hello(payload)
            if sni:
                rec["sni"] = sni
                rec["l7"] = "tls"
                rec["info"] = f"SNI={sni}"
            if ja3:
                rec["ja3"] = ja3
                rec["l7"] = rec["l7"] or "tls"
    elif proto_num == 17 and len(l4) >= 8:  # UDP
        rec["src_port"] = struct.unpack("!H", l4[0:2])[0]
        rec["dst_port"] = struct.unpack("!H", l4[2:4])[0]
        rec["proto"] = "UDP"
        payload = l4[8:]
        rec["l7"] = app_from_ports(rec["src_port"], rec["dst_port"], "UDP")
        if rec["src_port"] == 53 or rec["dst_port"] == 53:
            q = _dns_qname(payload)
            rec["l7"] = "dns"
            rec["info"] = q
            rec["dns_answers"] = _dns_answers(payload)
    elif proto_num == 1 and len(l4) >= 4:  # ICMP
        rec["proto"] = "ICMP"
        rec["l7"] = "icmp"
        rec["info"] = f"type={l4[0]} code={l4[1]}"
        payload = l4[8:]
    elif proto_num == 58:
        rec["proto"] = "ICMPv6"
        rec["l7"] = "icmp"
        payload = l4

    rec["payload_len"] = len(payload)
    rec["payload"] = payload
    rec["dns_answers"] = rec.get("dns_answers") or []
    if store_payload and payload:
        rec["payload_hex"] = payload[:payload_max].hex()
        rec["payload_ascii"] = _ascii_preview(payload, payload_max)
    else:
        rec["payload_hex"] = None
        rec["payload_ascii"] = None
    return rec


def parse_tshark_line(line: str, fields: list[str]) -> dict[str, Any] | None:
    parts = line.rstrip("\n").split("\t")
    if not parts or not parts[0]:
        return None
    # pad
    while len(parts) < len(fields):
        parts.append("")
    raw = dict(zip(fields, parts))

    def g(*keys: str) -> str:
        for k in keys:
            v = raw.get(k, "")
            if v:
                return v
        return ""

    ts_s = g("frame.time_epoch")
    try:
        ts = float(ts_s)
    except ValueError:
        return None
    length_s = g("frame.len") or "0"
    try:
        length = int(length_s)
    except ValueError:
        length = 0
    vlan_s = g("vlan.id")
    vlan = int(vlan_s) if vlan_s.isdigit() else None
    src_ip = g("ip.src", "ipv6.src") or None
    dst_ip = g("ip.dst", "ipv6.dst") or None
    proto_s = g("ip.proto")
    ip_proto = int(proto_s) if proto_s.isdigit() else None
    sport_s = g("tcp.srcport", "udp.srcport")
    dport_s = g("tcp.dstport", "udp.dstport")
    sport = int(sport_s) if sport_s.isdigit() else None
    dport = int(dport_s) if dport_s.isdigit() else None
    flags_s = g("tcp.flags")
    tcp_flags = None
    if flags_s:
        try:
            tcp_flags = int(flags_s, 0)
        except ValueError:
            tcp_flags = None
    col = g("_ws.col.Protocol") or PROTO_IP.get(ip_proto or -1, "OTHER")
    l7 = (g("dns.qry.name") and "dns") or (g("http.host") and "http") or (
        g("tls.handshake.extensions_server_name") and "tls"
    )
    info = g("dns.qry.name") or g("http.request.method") or g("tls.handshake.extensions_server_name") or flags_str(tcp_flags)
    if g("http.request.method"):
        info = f"{g('http.request.method')} {g('http.request.uri')} host={g('http.host')}".strip()
    ttl_s = g("ip.ttl")
    rec = {
        "ts": ts,
        "src_mac": g("eth.src") or None,
        "dst_mac": g("eth.dst") or None,
        "vlan": vlan,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "proto": col.upper() if col else "OTHER",
        "ip_proto": ip_proto,
        "length": length,
        "tcp_flags": tcp_flags,
        "ttl": int(ttl_s) if ttl_s.isdigit() else None,
        "l7": l7 or app_from_ports(sport, dport, col),
        "is_retrans": 1 if g("tcp.analysis.retransmission") else 0,
        "payload_len": 0,
        "info": info or None,
        "ja3": g("tls.handshake.ja3") or None,
        "sni": g("tls.handshake.extensions_server_name") or None,
        "http_host": g("http.host") or None,
        "dns_answers": [],
        "payload": b"",
        "tcp_seq": int(g("tcp.seq")) if g("tcp.seq").isdigit() else None,
        "tcp_ack": None,
        "payload_hex": None,
        "payload_ascii": None,
    }
    qname = g("dns.qry.name")
    for ans_ip in (g("dns.a"), g("dns.aaaa")):
        if ans_ip and qname:
            rec["dns_answers"].append((ans_ip.split(",")[0].strip(), qname))
    if rec["proto"] in ("TCP", "UDP", "ICMP", "ARP", "HTTP", "TLS", "DNS", "SSH"):
        if rec["proto"] in ("HTTP", "TLS", "SSH"):
            rec["l7"] = rec["proto"].lower()
            rec["proto"] = "TCP"
        elif rec["proto"] == "DNS":
            rec["l7"] = "dns"
            rec["proto"] = "UDP" if rec["ip_proto"] == 17 else rec["proto"]
    return rec


def name_bindings(pkt: dict[str, Any]) -> list[tuple[str, str]]:
    """IP → hostname pairs observed on this packet (SNI, HTTP Host, DNS A/AAAA)."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ip: str | None, name: str | None) -> None:
        host = clean_hostname(name)
        addr = (ip or "").strip()
        if not addr or not host:
            return
        key = (addr, host)
        if key in seen:
            return
        seen.add(key)
        out.append((addr, host))

    dst = pkt.get("dst_ip")
    add(dst, pkt.get("sni"))
    add(dst, pkt.get("http_host"))
    info = pkt.get("info") or ""
    if "host=" in info.lower() and dst:
        for part in info.split():
            if part.lower().startswith("host="):
                add(dst, part.split("=", 1)[1])
    for ip, name in pkt.get("dns_answers") or []:
        add(ip, name)
    return out


TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "vlan.id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "ip.ttl",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.seq",
    "tcp.analysis.retransmission",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "http.host",
    "http.request.method",
    "http.request.uri",
    "tls.handshake.extensions_server_name",
    "_ws.col.Protocol",
]
