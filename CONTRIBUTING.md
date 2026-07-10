# Contributing

Full contributing guide (commit format, governance rules for the .claude/ control plane, PR process): see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

Quick version:
- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before touching governance-critical paths (`apps/api`, `services/runner`, `packages/contracts`).
- - Run `./scripts/proof-test.sh` before opening a PR that touches enforcement logic.
  - - Changes to `packages/contracts` (the schema source of truth) require updating both Python and TypeScript consumers in the same PR.
    - 
