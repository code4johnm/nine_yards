"""Minimal PCAP (microsecond) writer/reader plus packet builders for demo traffic.

Checksums are computed so Wireshark/tshark can dissect the files cleanly.
No application secrets or exploit payloads are generated — HTTP/DNS/TLS
bodies are short, benign metadata.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Callable, Iterable, Iterator

PCAP_GLOBAL = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ipv4_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def ethernet(src: str, dst: str, ethertype: int, payload: bytes, vlan: int | None = None) -> bytes:
    if vlan is not None:
        hdr = mac_bytes(dst) + mac_bytes(src) + struct.pack("!HHH", ETH_VLAN, vlan & 0x0FFF, ethertype)
        return hdr + payload
    return mac_bytes(dst) + mac_bytes(src) + struct.pack("!H", ethertype) + payload


def ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    ttl: int = 64,
    ident: int = 0x1A2B,
    dscp: int = 0,
) -> bytes:
    ihl = 5
    total = ihl * 4 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        dscp,
        total,
        ident,
        0,
        ttl,
        proto,
        0,
        ipv4_bytes(src),
        ipv4_bytes(dst),
    )
    csum = _checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    return ipv4_bytes(src) + ipv4_bytes(dst) + struct.pack("!BBH", 0, proto, len(payload)) + payload


def tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
    ttl: int = 64,
) -> bytes:
    offset = 5 << 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset, flags, window, 0, 0)
    csum = _checksum(_pseudo(src, dst, 6, hdr + payload))
    hdr = hdr[:16] + struct.pack("!H", csum) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload, ttl=ttl)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes, ttl: int = 64) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    csum = _checksum(_pseudo(src, dst, 17, hdr + payload))
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), csum)
    return ipv4(src, dst, 17, hdr + payload, ttl=ttl)


def icmp_echo(src: str, dst: str, ident: int = 1, seq: int = 1, payload: bytes = b"ping", ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    csum = _checksum(hdr)
    hdr = struct.pack("!BBHHH", 8, 0, csum, ident, seq) + payload
    return ipv4(src, dst, 1, hdr, ttl=ttl)


def arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    sha = mac_bytes(src_mac)
    spa = ipv4_bytes(src_ip)
    tpa = ipv4_bytes(dst_ip)
    payload = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 1) + sha + spa + (b"\x00" * 6) + tpa
    return ethernet(src_mac, "ff:ff:ff:ff:ff:ff", ETH_ARP, payload)


def dns_query(name: str, qtype: int = 1) -> bytes:
    tid = 0x3344
    flags = 0x0100
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ip: str) -> bytes:
    tid = 0x3344
    flags = 0x8180
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q = labels + struct.pack("!HH", 1, 1)
    rr = labels + struct.pack("!HHIH", 1, 1, 60, 4) + ipv4_bytes(ip)
    return struct.pack("!HHHHHH", tid, flags, 1, 1, 0, 0) + q + rr


def http_req(method: str, path: str, host: str, extra: str = "") -> bytes:
    body = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nids-demo/1.0\r\n{extra}\r\n"
    return body.encode()


def http_resp(code: int = 200, body: str = "ok", ctype: str = "text/plain") -> bytes:
    raw = body.encode()
    hdr = (
        f"HTTP/1.1 {code} OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n"
    )
    return hdr.encode() + raw


def tls_client_hello(sni: str, ciphers: list[int] | None = None) -> bytes:
    """Minimal TLS 1.2 ClientHello with SNI so L7 metadata/JA3 can be extracted."""
    ciphers = ciphers or [0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0xC02B, 0xC02C, 0x009E, 0x0035]
    ver = b"\x03\x03"
    random = b"\x11" * 32
    session_id = b"\x00"
    cs = struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    comp = b"\x01\x00"
    # extensions: SNI, elliptic_curves, ec_point_formats, signature_algs
    host = sni.encode()
    sni_list = struct.pack("!BH", 0, len(host)) + host
    sni_ext = struct.pack("!HHH", 0, len(sni_list) + 2, len(sni_list)) + sni_list
    groups = struct.pack("!HHHHH", 0x000A, 8, 6, 0x001D, 0x0017) + struct.pack("!H", 0x0018)
    # actually pack properly
    curves = b"\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18"
    ecpf = b"\x00\x0b\x00\x02\x01\x00"
    sigalgs = b"\x00\x0d\x00\x0a\x00\x08\x04\x03\x08\x04\x04\x01\x05\x01"
    exts = sni_ext + curves + ecpf + sigalgs
    ext_blob = struct.pack("!H", len(exts)) + exts
    body = ver + random + session_id + cs + comp + ext_blob
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16" + ver + struct.pack("!H", len(hs)) + hs
    return rec


def ja3_from_client_hello(payload: bytes) -> str | None:
    """Compute JA3 MD5 from a TLS record containing ClientHello. Returns None if not parseable."""
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        rec_len = int.from_bytes(payload[3:5], "big")
        hs = payload[5 : 5 + rec_len]
        if not hs or hs[0] != 0x01:
            return None
        hs_len = int.from_bytes(b"\x00" + hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        ver = int.from_bytes(body[0:2], "big")
        i = 2 + 32  # random
        sid_len = body[i]
        i += 1 + sid_len
        cs_len = int.from_bytes(body[i : i + 2], "big")
        i += 2
        ciphers = [str(int.from_bytes(body[j : j + 2], "big")) for j in range(i, i + cs_len, 2)]
        i += cs_len
        comp_len = body[i]
        i += 1 + comp_len
        ext_ids: list[str] = []
        curves: list[str] = []
        points: list[str] = []
        if i + 2 <= len(body):
            ext_len = int.from_bytes(body[i : i + 2], "big")
            i += 2
            end = i + ext_len
            while i + 4 <= end:
                etype = int.from_bytes(body[i : i + 2], "big")
                elen = int.from_bytes(body[i + 2 : i + 4], "big")
                edata = body[i + 4 : i + 4 + elen]
                ext_ids.append(str(etype))
                if etype == 10 and len(edata) >= 2:
                    glen = int.from_bytes(edata[0:2], "big")
                    for j in range(2, 2 + glen, 2):
                        curves.append(str(int.from_bytes(edata[j : j + 2], "big")))
                if etype == 11 and len(edata) >= 1:
                    n = edata[0]
                    points = [str(b) for b in edata[1 : 1 + n]]
                i += 4 + elen
        s = f"{ver},{'-'.join(ciphers)},{'-'.join(ext_ids)},{'-'.join(curves)},{'-'.join(points)}"
        return hashlib.md5(s.encode()).hexdigest()
    except Exception:
        return None


def extract_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        rec_len = int.from_bytes(payload[3:5], "big")
        hs = payload[5 : 5 + rec_len]
        if not hs or hs[0] != 0x01:
            return None
        hs_len = int.from_bytes(b"\x00" + hs[1:4], "big")
        body = hs[4 : 4 + hs_len]
        i = 2 + 32
        i += 1 + body[i]
        cs_len = int.from_bytes(body[i : i + 2], "big")
        i += 2 + cs_len
        i += 1 + body[i]
        ext_len = int.from_bytes(body[i : i + 2], "big")
        i += 2
        end = i + ext_len
        while i + 4 <= end:
            etype = int.from_bytes(body[i : i + 2], "big")
            elen = int.from_bytes(body[i + 2 : i + 4], "big")
            edata = body[i + 4 : i + 4 + elen]
            if etype == 0 and len(edata) >= 5:
                # SNI list
                ntype = edata[2]
                nlen = int.from_bytes(edata[3:5], "big")
                if ntype == 0:
                    return edata[5 : 5 + nlen].decode("utf-8", "replace")
            i += 4 + elen
    except Exception:
        return None
    return None


class PcapWriter:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.path.open("wb")
        self._fp.write(PCAP_GLOBAL)
        self.count = 0

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        n = len(frame)
        self._fp.write(struct.pack("<IIII", sec, usec, n, n))
        self._fp.write(frame)
        self.count += 1

    def close(self) -> None:
        self._fp.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_pcap(path: Path) -> Iterator[tuple[float, bytes]]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
        ns = False
    elif magic == 0xD4C3B2A1:
        endian = ">"
        ns = False
    elif magic == 0xA1B23C4D:
        endian = "<"
        ns = True
    else:
        raise ValueError(f"unsupported pcap magic {magic:#x} in {path}")
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        frame = data[off : off + incl]
        off += incl
        ts = sec + (frac / 1_000_000_000 if ns else frac / 1_000_000)
        yield ts, frame


def frames_to_pcap(path: Path, frames: Iterable[tuple[float, bytes]]) -> int:
    n = 0
    with PcapWriter(path) as w:
        for ts, frame in frames:
            w.write(ts, frame)
            n += 1
    return n
