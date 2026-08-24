# 9yards NIDS — Secure Software Engineering Baseline

**Product:** 9yards NIDS  
**Baseline package version:** 0.1.0  
**Date:** 2026-08-24  
**Status:** Engineering baseline (not an authorization decision)  
**Classification of this package:** Unclassified / public-methods only

This package is an auditable engineering baseline for **9yards NIDS**, a defensive network monitoring and statistical detection dashboard. It is stack-agnostic in control intent and instantiated against the current FastAPI + SQLite + local-UI implementation.

## Authority limits

This work is **not** an official U.S. Government issuance. It:

- does **not** grant or imply Authorization to Operate (ATO);
- does **not** create collection authorities under Executive Order 12333;
- does **not** publish key material, exploit methods, or classified configurations;
- does **not** claim STIG certification, FIPS 140 module validation, Common Criteria, ISO 27001 certification, or safety/medical certification;
- is **not** written in the voice of an authorizing official, intelligence officer, or catalog publisher.

Department of Defense (DoD) is used as the statutory name. “Department of War (DoW)” is not used unless a deploying program’s authorized language requires that secondary title.

## Package contents

| Relative path | Content |
| --- | --- |
| `VERSION` | Baseline package version |
| `README.md` | This index and authority limits |
| `docs/01-requirements-and-architecture.md` | Requirements analysis and high-level architecture |
| `docs/02-project-structure.md` | Recommended repository topology, CI/CD, C-SCRM |
| `docs/03-compliance-traceability-seed.md` | Seed traceability matrix |
| `conf/profiles.yml` | `dev` / `audit` / `prod` profile contract |
| `conf/sbom-policy.yml` | CISA 2026 SBOM + VEX policy skeleton |

Subsequent increments (hardening guide, release procedures, runtime ops, test plan, SBOM examples, full CTM) are **out of this increment** and will be produced on request.

## How to use

1. Treat `docs/01-requirements-and-architecture.md` as the system-level baseline for design reviews.
2. Align the repository and pipeline with `docs/02-project-structure.md`.
3. Expand `docs/03-compliance-traceability-seed.md` to enhancement and test-ID granularity during implementation.
4. Instantiate `conf/profiles.yml` and `conf/sbom-policy.yml` as **rebuild/redeploy** artifacts, not live runtime toggles that weaken prod.

Substitute `/workspace/project` with the actual checkout path.

Privacy: paths and identifiers generalized.
