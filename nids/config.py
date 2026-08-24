"""Runtime configuration. Bind localhost by default; never store full payloads unless asked."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return default if v is None or v == "" else v


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return int(v)


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    data_dir: Path = Path(".")
    bind_public: bool = False
    iface: str = "any"
    bpf: str = ""
    live_enabled: bool = False
    store_pcap: bool = False
    pcap_rotate_mb: int = 50
    pcap_rotate_files: int = 8
    payload_enabled: bool = False
    payload_max_bytes: int = 256
    max_packets: int = 250_000
    max_flows: int = 80_000
    max_alerts: int = 40_000
    stats_keep_hours: int = 48
    flow_idle_sec: float = 60.0
    flow_max_sec: float = 600.0
    suricata_eve: str = ""
    zeek_dir: str = ""
    syslog_path: str = ""
    api_token: str = ""
    autoload_demo: bool = True

    @property
    def capture_dir(self) -> Path:
        return self.data_dir / "capture"

    @property
    def log_path(self) -> Path:
        return self.data_dir / "nids.log"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "nids.db"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.capture_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
            os.chmod(self.capture_dir, 0o700)
        except OSError:
            pass


def load_settings() -> Settings:
    root = _root()
    bind_public = _env_bool("NIDS_BIND_PUBLIC", False)
    host = _env("NIDS_HOST", "127.0.0.1")
    if not bind_public:
        host = "127.0.0.1"
    s = Settings(
        host=host,
        port=_env_int("NIDS_PORT", 8787),
        data_dir=Path(_env("NIDS_DATA_DIR", str(root / "data"))).expanduser().resolve(),
        bind_public=bind_public,
        iface=_env("NIDS_IFACE", "any"),
        bpf=_env("NIDS_BPF", ""),
        live_enabled=_env_bool("NIDS_LIVE", False),
        store_pcap=_env_bool("NIDS_STORE_PCAP", False),
        pcap_rotate_mb=_env_int("NIDS_PCAP_ROTATE_MB", 50),
        pcap_rotate_files=_env_int("NIDS_PCAP_FILES", 8),
        payload_enabled=_env_bool("NIDS_STORE_PAYLOAD", False),
        payload_max_bytes=_env_int("NIDS_PAYLOAD_MAX", 256),
        max_packets=_env_int("NIDS_MAX_PACKETS", 250_000),
        max_flows=_env_int("NIDS_MAX_FLOWS", 80_000),
        max_alerts=_env_int("NIDS_MAX_ALERTS", 40_000),
        suricata_eve=_env("NIDS_SURICATA_EVE", ""),
        zeek_dir=_env("NIDS_ZEEK_DIR", ""),
        syslog_path=_env("NIDS_SYSLOG", ""),
        api_token=_env("NIDS_TOKEN", ""),
        autoload_demo=_env_bool("NIDS_AUTODEMO", True),
    )
    s.ensure_dirs()
    return s
