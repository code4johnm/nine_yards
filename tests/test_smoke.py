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
from nids.parser import name_bindings, parse_frame
from nids.pcapio import dns_response, ethernet, ja3_from_client_hello, tcp, tls_client_hello, udp


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

    def test_dns_tldn_binding(self) -> None:
        frame = ethernet(
            "02:50:01:00:00:30", "02:50:01:00:00:10", 0x0800,
            udp("10.50.1.30", "10.50.1.10", 53, 40000, dns_response("www.lab.example", "10.50.1.20")),
        )
        pkt = parse_frame(1.0, frame)
        self.assertIsNotNone(pkt)
        self.assertIn(("10.50.1.20", "www.lab.example"), name_bindings(pkt))

    def test_sni_tldn_binding(self) -> None:
        frame = ethernet(
            "02:50:01:00:00:10", "02:00:00:00:00:50", 0x0800,
            tcp("10.50.1.10", "203.0.113.10", 52000, 443, 1, 1, 0x18, tls_client_hello("update.lab.example")),
        )
        pkt = parse_frame(1.0, frame)
        self.assertIsNotNone(pkt)
        self.assertIn(("203.0.113.10", "update.lab.example"), name_bindings(pkt))

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
