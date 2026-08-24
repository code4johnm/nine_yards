# 9yards NIDS — Compliance Traceability Seed Matrix

**Document ID:** 9YARDS-CTM-001  
**Version:** 0.1.0  
**Date:** 2026-08-24  
**Status:** Seed — expandable to control-enhancement and test-ID granularity  
**Authority:** Engineering mapping only; not an authorization record

Legend:

- **I** = implemented in current 9yards NIDS tree (lab)
- **P** = policy defined in this baseline; implementation pending
- **N** = not applicable (rationale required)

IO/privacy notes are design constraints (EO 12333 publicly citable identifier only).

## Seed matrix

| Feature / FR | NIST SP 800-53 Rev. 5 (primary) | SSDF 800-218 | CISA / SBOM 2026 | IO / privacy | State |
| --- | --- | --- | --- | --- | --- |
| Loopback bind default FR-01 | SC-7, CM-6, CM-7 | PW.9 | Secure defaults | Reduces exposure of metadata | I |
| Payload storage off FR-02 | SI-12, AU-11, SC-8 analog (no content) | PW.5 | Minimize attack surface | No content collection by default | I |
| Restrictive `data/` modes FR-03 | AC-3, SC-28 | PW.9 | — | Limits access to incidental identifiers | I (intent; FS may ignore mode) |
| dumpcap-only raw caps FR-04 | AC-6, AC-5 | PW.1 | Least privilege | Capture helper ≠ API principal | I |
| Optional API token FR-05 | IA-5, AC-3, SC-12 | PS.1 | — | Access control on metadata API | I (optional) |
| DEMO labeling FR-06 | SI-10, AU-10 | RV.1 | Honesty in evidence | Prevents DEMO treated as USP intel | I |
| Health endpoint FR-07 | SI-4, CA-7, AU-12 | RV.1 | — | Ops telemetry, not USP | I |
| Rotating logs, no secrets FR-08 | AU-2, AU-3, AU-11 | PW.8 | — | Minimized audit | I (partial) |
| Pinned deps FR-09 | SA-15, SR-3, CM-2 | PS.3, PW.4 | Component version+hash | — | P |
| SPDX 3.x SBOM + VEX FR-10 | SR-4, SA-15, SI-5 | PS.3, PW.4 | All 2026 minimum elements | SBOM has no PCAP content | P |
| Signed artifacts FR-11 | SA-10, SC-13, CM-5 | PS.2, PW.6 | SBOM author signature | — | P |
| Attributable ack/mute FR-12 | AU-3, AU-9, AC-2 | PW.8 | — | Accountability vs collection | P |
| Geo off without MMDB FR-13 | SI-12, PM-25 | PW.5 | — | No location of persons via IP | I |
| Untrusted ingest FR-14 | SI-10, SI-3, SR-11 | PW.4 | C-SCRM for files | Do not execute PCAPs | I (size cap) |
| Fail closed prod FR-15 | CM-6, SI-17 | PW.9 | Pipeline enforcement | — | P |
| Threat model STRIDE | RA-3, SA-8 | PO.1, PW.1 | Secure by Design | In-scope adversaries only | I (this package) |
| Profiles dev/audit/prod | CM-2, CM-6 | PO.5, PW.9 | Rebuild not runtime weaken | Prod forbids payload/public bind | P (YAML seed) |
| C-SCRM intake records | SR-1, SR-3, SR-5 | PS.3 | Component producer/name/version | — | P |
| No secrets in git | IA-5(7), SA-9 | PS.1 | — | Tokens not in SBOM or repo | I (.gitignore) |
| Signed updates / rollback | SI-2, CM-3, CP-10 | RV.2 | Artifact+SBOM pair | — | P (manual tag) |
| Web UI ASVS mapping | SC-7, SI-10, AC-3 | PW.2 | — | No third-party script CDN | I (local JS) |
| SP 800-218A generative AI | SA-8, SI-7 analog | — | SBOM-for-AI | Model data IO | N — no FM in v1.0.0 |
| SP 800-204 microservices | SC-7, AC-4 | PW.9 | — | — | N — monolith; reopen if split |
| SP 800-63 digital identity | IA-2, IA-5, IA-8 | PO.3 | — | Operator ≠ monitored person | N until off-loopback admin |
| IEC 62443 / ISO 21434 / 62304 | — | — | — | — | N — not ICS/auto/medical |
| CNSSI 1253 NSS overlay | — | — | — | — | N unless program NSS |
| STIG certification claim | CM-6 | — | — | — | N — benchmarks only |
| ATO / eMASS package | CA-6 | — | — | — | N — out of increment |

## CISA 2026 SBOM minimum elements — coverage seed

| Element | 9yards NIDS plan | State |
| --- | --- | --- |
| SBOM author signature | Sign SPDX JSON with release key | P |
| SBOM tool name and version | Record in SBOM creationInfo / tool | P |
| SBOM data format name and version | `spdx+json` / SPDX 3.x | P |
| SBOM generation context (lifecycle) | `build` for release; `source` optional | P |
| Component producer | Package supplier / OS vendor | P |
| Component name | e.g. `fastapi`, `tshark` | P |
| Component version | Pinned | P |
| Component hash and algorithm | SHA-256 | P |
| Component license | SPDX license id | P |
| Full transitive, no depth limit | Resolver + OS inventory | P |
| VEX for known CVEs | Sidecar next to artifact | P |
| SBOM stored with artifact | `dist/*.spdx.json` beside wheel/image | P |

## Expansion path

Later increment: one row per **control enhancement** (e.g. AC-6(1), AU-3(1)) and one **test ID** (`T-BIND-01`) with automated pass/fail in CI.

---

*End of 9YARDS-CTM-001 v0.1.0*
