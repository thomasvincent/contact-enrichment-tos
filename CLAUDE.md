# CLAUDE.md

## Purpose
Production-grade contact enrichment backend for Trusted Operating Environments with data provenance, sharing ledger, and regulatory compliance (GDPR, CCPA, LGPD).

## Stack
- Multi-language implementations: Go, Java, Python, Rust
- Deployments: Docker, Helm, Nomad
- SELinux integration, zero-trust architecture
- Makefile-based build

## Build & Test
```bash
make
```

## Conventions
- Implementation per language in `implementations/`
- Deployment configs in `deployments/`
- Documentation in `docs/`
- Security-first: MAC, cryptographic provenance, HSM-signed audit trails
