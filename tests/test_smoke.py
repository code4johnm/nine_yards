"""Offline smoke: generate DEMO PCAP, ingest, assert packets/flows/alerts exist."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nids.db import Store
from nids.demo import generate_frames, ingest_frames, write_sample_files
from nids.parser import parse_frame
from nids.pcapio import ja3_from_client_hello, tls_client_hello


class DemoSmoke(unittest.TestCase):
    def test_frames_parse(self) -> None:
        frames = generate_frames(now=1_700_000_000.0)
        self.assertGreater(len(frames), 100)
        parsed = 0
        protos = set()
        vlan = 0
        for ts, frame in frames:
            pkt = parse_frame(ts, frame)
            self.assertIsNotNone(pkt)
            parsed += 1
            protos.add(pkt["proto"])
            if pkt.get("vlan") is not None:
                vlan += 1
        self.assertGreater(parsed, 100)
        self.assertTrue({"TCP", "UDP", "ICMP", "ARP"} <= protos)
        self.assertGreater(vlan, 0)

    def test_ja3(self) -> None:
        hello = tls_client_hello("update.lab.example")
        self.assertIsNotNone(ja3_from_client_hello(hello))

    def test_db_ingest(self) -> None:
        frames = generate_frames(now=1_700_000_000.0)
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "t.db")
            stats = ingest_frames(store, frames)
            self.assertGreater(stats["packets"], 100)
            self.assertGreater(stats["flows"], 10)
            self.assertGreater(stats["alerts"], 5)
            demo = store.scalar("SELECT COUNT(*) FROM alerts WHERE is_demo=1")
            self.assertGreater(demo, 0)
            write_sample_files(frames)
            self.assertTrue((ROOT / "sample" / "lab-demo.pcap").exists())


if __name__ == "__main__":
    unittest.main()
