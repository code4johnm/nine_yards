# Operator guide

What each panel is for, and what an analyst should actually look at.

## Time range and search

The global picker (5m / 15m / 1h / 6h / 24h) scopes **every** table and chart. Search matches IPs, signatures, SNI, and info strings. Pause auto-refresh before screenshotting a hunt.

If the DEMO banner is showing, treat signatures as labeled exercises, not production detections.

## Overview

| KPI | Meaning | Hunt hint |
| --- | --- | --- |
| pps / bps | Instantaneous (live) or range-average (demo) | Sudden spikes vs the sparkline; compare to the Protocols z-score |
| active flows | Open 5-tuples | Growth without byte growth → scans |
| alert rate | Alerts / second in the engine | Sustained rate + one source IP → lock onto that host |
| unique hosts | IPs seen in range | Explosion of destinations from one orig = horizontal scan |
| drops / errors | Kernel `rx_dropped` / `rx_errors` | Non-zero drops = you are blind; reduce BPF or move off `any` |

**Top talkers / destinations** — elephant flows and C2 often hide here more than in the alert feed.

**Latest alerts** — triage by severity color: Critical/High first, then recon.

## Packets

Metadata table, not a Wireshark replacement.

- Filter by IP/port/proto.
- Click a row for JSON + optional payload viewer (disabled by default).
- `RETRANS` marks duplicate TCP seq or tshark retransmission analysis.
- VLAN column is filled when 802.1Q is present (demo includes VLAN 80 on the internal HTTP conversation).

Look for: SYN-only bursts, NULL/FIN flags, DNS qnames that do not belong on the lab net, SNI that does not match the dest IP’s role.

## Flows

Bidirectional conversations. Orig is whoever sent the first packet we saw.

| View | Definition | Hunt hint |
| --- | --- | --- |
| Elephant | ≥ 100 KB | Data movement; confirm business reason |
| Scan-like | TCP, ≤3 packets, ≤240 bytes, SYN seen | Map orig → many dest ports/hosts |
| Long-lived | duration ≥ 30s | Sessions, tunnels, beacons |
| Short-lived | duration < 2s | Scans, failed connects, health checks |

RST rate and retrans counts on a single flow are on the row (open the JSON). Click orig→resp to see related packets.

## Alerts

Severity coloring: Critical / High / Medium / Low / Info.

- **Ack** = “I saw this” (hidden from default feed).
- **Mute** = stop this SID+src+dst from occupying the feed.
- **Comment** via API `POST /api/alerts/{id}/comment`.
- `DEMO` pill means the row was generated or imported as sample EVE.

Top signatures / alerting hosts / victims on this page are the fastest way to answer “is this one noisy rule or one noisy host?”

Correlate: click signature → JSON includes `flow_id` / `packet_id` when the statistical engine fired on live packets.

## Protocols

- Mix pie: L7 tag if known, else L4.
- TCP flag histogram: SYN without ACK mass = scan/flood.
- Size histogram: lots of 60–64 B packets = control/scan; jumbo/1514 = transfer.
- Inter-arrival p50/p95: very regular p50 with low spread on one host pair → beaconing (also a STAT signature).
- Port heatmap: unexpected high ports as servers.
- Geo is stubbed unless a GeoLite2 MMDB is installed (this Kali image has legacy `GeoIP.dat` only).

## Hosts

One row per IP. Bytes out vs in tells you who is uploading. Alert count is a roll-up, not a priority by itself. Click an IP for conversations + recent alerts.

## Settings / capture health

- **Start live** uses dumpcap/tshark. Failures (permissions, missing iface) appear as `last_error`.
- **Load DEMO** wipes telemetry and rebuilds the lab PCAP + alerts.
- **Upload PCAP** is metadata ingest only (80 MB cap).
- Health JSON is the same document as `GET /api/health` — use it from systemd or a watchdog.

## Suggested first hunt on the DEMO set

1. Overview → High/Critical alerts on `10.50.1.99` (scanner) and `10.50.1.77` (beaconing IoT).
2. Flows → Scan-like and Elephant views.
3. Packets → filter `10.50.1.99`, watch SYN / RST.
4. Protocols → TCP flag bar (SYN vs SYN-ACK vs RST).
5. Hosts → `203.0.113.50` (TEST-NET-3 documentation prefix used as fake C2).
