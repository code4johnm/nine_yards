"""Shared helpers: logging, time windows, formatting, private-IP checks."""

from __future__ import annotations

import ipaddress
import logging
import math
import os
import shutil
import subprocess
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

TCP_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)

PROTO_IP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    123: "ntp",
    137: "netbios",
    139: "smb",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    6443: "k8s",
    8080: "http-alt",
    8443: "https-alt",
    9200: "es",
}


def utc_now() -> float:
    return datetime.now(timezone.utc).timestamp()


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


def parse_range(range_key: str | None, custom_from: float | None = None, custom_to: float | None = None) -> tuple[float, float]:
    now = utc_now()
    if custom_from and custom_to and custom_to > custom_from:
        return custom_from, custom_to
    mapping = {
        "5m": 300,
        "15m": 900,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }
    sec = mapping.get((range_key or "15m").lower(), 900)
    return now - sec, now


def flags_str(raw: int | None) -> str:
    if not raw:
        return ""
    names = [n for bit, n in TCP_FLAG_NAMES if raw & bit]
    return ",".join(names)


def app_from_ports(sport: int | None, dport: int | None, proto: str | None) -> str:
    for p in (dport, sport):
        if p and p in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[p]
    if proto:
        return proto.lower()
    return "unknown"


def clean_hostname(name: str | None) -> str | None:
    """Normalize an observed DNS/SNI/HTTP name. Returns None if it is not a hostname."""
    if not name:
        return None
    name = str(name).strip().rstrip(".").lower()
    if not name or len(name) > 253:
        return None
    if "://" in name:
        name = name.split("://", 1)[1]
    name = name.split("/")[0].split("?")[0].split(":")[0].strip()
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    if any(c.isspace() or c in "<>\"'" for c in name):
        return None
    return name


def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        obj = ipaddress.ip_address(ip)
        return bool(obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved)
    except ValueError:
        return True


def which(name: str) -> str | None:
    return shutil.which(name)


def run_cmd(args: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def setup_logging(log_path: Path, level: str = "INFO") -> logging.Logger:
    log = logging.getLogger("nids")
    if log.handlers:
        return log
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass
    return log


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    m = sum(values) / len(values)
    if len(values) < 2:
        return m, 0.0
    var = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return m, math.sqrt(var)


def zscore(value: float, hist: list[float]) -> float | None:
    m, s = mean_std(hist)
    if s < 1e-9:
        return None
    return (value - m) / s


def iface_stats(iface: str) -> dict[str, int]:
    """Read kernel counters for capture-health. `any` has no sysfs node."""
    out = {"rx_packets": 0, "rx_bytes": 0, "rx_dropped": 0, "rx_errors": 0, "tx_packets": 0}
    if not iface or iface == "any":
        base = Path("/sys/class/net")
        if not base.exists():
            return out
        for child in base.iterdir():
            if child.name == "lo":
                continue
            part = iface_stats(child.name)
            for k, v in part.items():
                out[k] += v
        return out
    base = Path(f"/sys/class/net/{iface}/statistics")
    if not base.exists():
        return out
    for key in list(out):
        p = base / key
        try:
            out[key] = int(p.read_text().strip())
        except (OSError, ValueError):
            pass
    return out


def list_ifaces() -> list[dict[str, Any]]:
    ifaces: list[dict[str, Any]] = []
    code, stdout, _ = run_cmd(["dumpcap", "-D"])
    if code == 0 and stdout.strip():
        for line in stdout.splitlines():
            # "1. wlan0" or "1. wlan0 (description)"
            rest = line.split(".", 1)[-1].strip()
            name = rest.split()[0] if rest else rest
            if name:
                ifaces.append({"name": name, "label": rest})
        return ifaces
    base = Path("/sys/class/net")
    if base.exists():
        for child in sorted(base.iterdir()):
            ifaces.append({"name": child.name, "label": child.name})
    return ifaces


def tool_versions() -> dict[str, Any]:
    tools = {}
    for name, args in (
        ("tshark", ["tshark", "--version"]),
        ("dumpcap", ["dumpcap", "-v"]),
        ("tcpdump", ["tcpdump", "--version"]),
        ("suricata", ["suricata", "--build-info"]),
        ("zeek", ["zeek", "--version"]),
        ("docker", ["docker", "--version"]),
    ):
        path = which(name)
        if not path:
            tools[name] = {"present": False, "path": None, "version": None}
            continue
        code, stdout, stderr = run_cmd(args)
        first = (stdout or stderr).splitlines()[0] if (stdout or stderr) else ""
        tools[name] = {"present": True, "path": path, "version": first[:200]}
    tools["python"] = {"present": True, "path": os.sys.executable, "version": os.sys.version.split()[0]}
    return tools
