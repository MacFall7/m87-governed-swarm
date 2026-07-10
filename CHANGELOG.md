# Changelog

This project does not yet publish tagged releases. This file tracks major governance-relevant changes on `main`.

## [Unreleased]

### Governance Hardening V1
- Runner-level enforcement: Deployment Envelope Hash (DEH) verification, autonomy budget, write-scope gating, egress hard-stop via `governed_request()`.
- - API Governance Phase 3-6: Redis-backed session risk tracking, code artifact inspection (tripwire scan), human override protection with proposal hash binding.
  - - UI fail-closed normalization boundary (`normalize.ts` as single entry point for governance data display).
   
    See [docs/PROOF_MAP.md](docs/PROOF_MAP.md) for the claim-to-mechanism-to-test mapping and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what's covered.
   
    ---

    Format loosely follows [Keep a Changelog](https://keepachangelog.com/). Once a first tagged release ships, this file will track versions against it.
    
