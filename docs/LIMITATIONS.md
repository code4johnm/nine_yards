# Limitations and next-step hardening

This is a lab/SOC **monitoring** dashboard, not a replacement for Suricata+Zeek+Arkime.

## Current limits

- **No full NSM engine.** Statistical detectors are heuristics with a local SID space (`9000000+`). They will false-positive on noisy LANs.
- **Suricata/Zeek are not required and were not installed on this host.** Importers exist; they tail files if you point `NIDS_SURICATA_EVE` / `NIDS_ZEEK_DIR` at them.
- **No Elasticsearch / Kibana.** SQLite will not survive multi-Gbps with full packet retention. Caps prune old rows (`NIDS_MAX_PACKETS` etc.).
- **Payload storage is off.** HTTP bodies, TLS records, and files are not reconstructed. The optional hex viewer is capped (`NIDS_PAYLOAD_MAX`).
- **JA3** is computed only when our parser sees a TLS ClientHello on the wire (demo traffic includes this). tshark JA3 needs the JA3 plugin; the field is requested if present.
- **Geo map stubbed.** `/usr/share/GeoIP/GeoIP.dat` is the legacy format; we do not ship MaxMind GeoLite2. Public-IP mapping is skipped.
- **No authentication by default** (localhost bind). Set `NIDS_TOKEN` behind your own reverse proxy if you expose it.
- **Single process.** One writer thread + SQLite WAL. Do not put it on a 10G tap without an external capture ring.
- **IPv6** is parsed for metadata but demo traffic is IPv4.
- **NetFlow/IPFIX:** no binary collector yet (TODO). Flows can be exported as CSV/JSON instead.
- **Syslog ingest** is a keyword filter, not a parser for every vendor.

## Hardening / next steps

1. Install Suricata with Emerging Threats Open (or your licensed set) and point `NIDS_SURICATA_EVE=/var/log/suricata/eve.json`.
2. Install Zeek; ship `conn.log`, `dns.log`, `http.log`, `ssl.log`, `notice.log` into `NIDS_ZEEK_DIR`.
3. Add JA3/JA4 via Zeek `ssl.log` or a tshark plugin; join on flow 5-tuple.
4. TLS metadata: cert subjects, JA3S, ALPN — best taken from Zeek, not payload dumps.
5. Drop capabilities further: run the API as unprivileged, keep only dumpcap privileged, feed a dedicated pcap directory.
6. Add mTLS or SSO at nginx/caddy in front of `:8787`; keep the app on `127.0.0.1`.
7. Persistent hunt notes: move ack/mute/comment to an audit table with operator identity.
8. GeoLite2-City.mmdb + optional map panel for non-private destinations only.
9. IPFIX collector (UDP 4739) if the lab already exports from a router.
10. Dedicated capture NIC, BPF pinned to the lab VLAN, and an `afpacket` Suricata worker beside this dashboard rather than instead of it.

## TODO stubs in code

- `nids/sensors.py` `_zeek_ssl`: TLS rows are not upserted as flows yet (conn.log already covers the 5-tuple).
- IPFIX/NetFlow binary ingest is not implemented; use Zeek conn or the flow CSV export.
- Payload viewer refuses unless `NIDS_STORE_PAYLOAD=1` (intentional).
