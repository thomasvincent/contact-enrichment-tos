# Contact Enrichment Platform - Trusted Operating System Edition

[![Security: TOS-Compliant](https://img.shields.io/badge/security-TOS--compliant-green.svg)](docs/security/TOS_COMPLIANCE.md)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

A production-grade contact enrichment backend designed for **Trusted Operating Environments** with comprehensive data provenance, sharing tracking, and regulatory compliance (GDPR, CCPA, LGPD).

## 🔒 Security Posture

- **Mandatory Access Control (MAC)**: SELinux integration with fine-grained security labels
- **Cryptographic Provenance**: Immutable, hash-chained ledger of data origin
- **Audit Trails**: HSM-signed, tamper-proof event logs
- **Zero-Trust Architecture**: Every operation authenticated, authorized, and audited
- **Defense in Depth**: Encryption at rest, in transit, and in memory

## 📚 Quick Navigation

| Document | Purpose |
|----------|---------|
| [Architecture Overview](docs/architecture/OVERVIEW.md) | System design and domain model |
| [Setup Guide](docs/setup/INSTALLATION.md) | Step-by-step installation |
| [API Documentation](docs/api/README.md) | REST API reference |
| [Security Guide](docs/security/SECURITY.md) | Security architecture and SELinux policies |
| [Operations Runbook](docs/operations/RUNBOOK.md) | Day-to-day operations |
| [Compliance Guide](docs/compliance/REGULATORY.md) | GDPR/CCPA compliance |

## 🎯 Core Features

### Data Provenance
- **Where did this data come from?** Complete chain of custody from acquisition to sharing
- **Cryptographic verification**: Tamper-proof provenance with Merkle tree anchoring
- **Vendor attribution**: Track which enrichment vendors provided which data points

### Sharing Ledger
- **Who has my data?** Immutable record of every data sharing event
- **DSR fulfillment**: GDPR Article 15 / CCPA compliance built-in
- **Purpose limitation**: Declared purpose tracked for every access

### TOS Integration
- **SELinux policies**: Type enforcement and multi-category security
- **Process isolation**: Sandboxed execution domains
- **Kernel-level MAC**: Security decisions enforced at OS level
- **Audit subsystem**: Integration with Linux auditd

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Contact Enrichment Platform                  │
├─────────────────────────────────────────────────────────────────┤
│  Contact Core │ Provenance │ Access    │ Audit  │ Enrichment   │
│  Domain       │ Ledger     │ Governance│ Trail  │ Pipeline     │
├─────────────────────────────────────────────────────────────────┤
│              Security Kernel (TCB Interface)                    │
├─────────────────────────────────────────────────────────────────┤
│          Trusted Operating System (RHEL + SELinux)              │
└─────────────────────────────────────────────────────────────────┘
```

See [Architecture Deep Dive](docs/architecture/OVERVIEW.md) for complete details.

## 🚀 Implementations

Four language implementations, each optimized for different operational requirements:

| Language | Branch | Use Case | Status |
|----------|--------|----------|--------|
| **Java** (Spring Boot) | `impl/java` | Enterprise integration, Spring ecosystem | ✅ Production |
| **Python** (FastAPI) | `impl/python` | Rapid development, ML integration | ✅ Production |
| **Go** | `impl/go` | High performance, low resource usage | ✅ Production |
| **Rust** | `impl/rust` | Maximum security guarantees, systems programming | ✅ Production |

All implementations share:
- Identical domain models (DDD)
- Same PostgreSQL schema
- Compatible API contracts (OpenAPI 3.0)
- Unified SELinux policies

## 📦 Technology Stack

### Core Infrastructure
- **OS**: Red Hat Enterprise Linux 9+ (SELinux enforcing)
- **Database**: PostgreSQL 15+ with Row-Level Security
- **Message Bus**: Apache Kafka (event sourcing)
- **Cache**: Redis (with encryption)
- **Secrets**: HashiCorp Vault or AWS Secrets Manager

### Security Components
- **HSM**: PKCS#11 compatible (Luna, AWS CloudHSM)
- **TLS**: Mutual TLS 1.3 with certificate pinning
- **Auth**: OAuth 2.0 / OIDC + mTLS for service-to-service
- **Encryption**: AES-256-GCM (data at rest), ChaCha20-Poly1305 (transit)

## 🛠️ Quick Start

### Prerequisites
- RHEL 9.x with SELinux in enforcing mode
- PostgreSQL 15+
- Docker (for development)
- Java 21+ / Python 3.11+ / Go 1.21+ / Rust 1.75+ (depending on implementation)

### Installation (Java Example)

```bash
# Clone repository
git clone https://github.com/yourusername/contact-enrichment-tos.git
cd contact-enrichment-tos

# Checkout Java implementation
git checkout impl/java

# Run setup script (installs SELinux policies, configures DB)
sudo ./scripts/setup.sh

# Build application
./mvnw clean package -DskipTests

# Configure secrets
export VAULT_TOKEN="your-vault-token"
./scripts/configure-secrets.sh

# Deploy SELinux policy
sudo ./scripts/selinux/install-policy.sh

# Start application
sudo systemctl start contact-enrichment

# Verify
curl -k https://localhost:8443/api/v1/health
```

See [detailed installation guide](docs/setup/INSTALLATION.md) for complete instructions.

## 🧪 Testing

```bash
# Unit tests
./mvnw test

# Integration tests (requires PostgreSQL)
./mvnw verify -P integration-tests

# Security tests
./mvnw verify -P security-tests

# SELinux policy tests
sudo ./scripts/selinux/test-policy.sh
```

## 📊 Monitoring & Operations

- **Health Checks**: `/api/v1/health`, `/api/v1/ready`
- **Metrics**: Prometheus endpoint at `/metrics`
- **Audit Logs**: Written to PostgreSQL + forwarded to SIEM
- **SELinux Alerts**: Monitored via `audit2why`

See [Operations Runbook](docs/operations/RUNBOOK.md).

## 🔐 Security

### Reporting Security Issues
**DO NOT** open public issues for security vulnerabilities.

Email: security@yourcompany.com (PGP key: [link])

### Security Scanning
- **SAST**: SonarQube, Semgrep
- **DAST**: OWASP ZAP
- **Dependency Scanning**: Snyk, Dependabot
- **Container Scanning**: Trivy, Grype
- **Secrets Detection**: TruffleHog, detect-secrets

## 📜 Compliance

- **GDPR**: Articles 15-22 (Data Subject Rights) fully supported
- **CCPA**: Consumer rights (access, deletion, opt-out) implemented
- **SOC 2 Type II**: Audit controls in place
- **HIPAA**: BAA-ready with encryption and access controls
- **ISO 27001**: Aligned security controls

See [Compliance Documentation](docs/compliance/REGULATORY.md).

## 🤝 Contributing

This is a private repository. See [CONTRIBUTING.md](CONTRIBUTING.md) for internal contribution guidelines.

All commits must:
- Follow [Conventional Commits](https://www.conventionalcommits.org/)
- Reference a GitHub issue
- Pass security scanning
- Include tests
- Be signed (GPG)

## 📄 License

Proprietary and confidential. See [LICENSE](LICENSE).

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Internal Wiki**: [Confluence link]
- **Slack**: #contact-enrichment-platform
- **On-call**: PagerDuty rotation

## 🗺️ Roadmap

See [GitHub Projects](https://github.com/yourusername/contact-enrichment-tos/projects) for current sprint.

### Q1 2025
- [ ] Add blockchain-based provenance anchoring
- [ ] Implement differential privacy for analytics
- [ ] Add support for ARM64 architecture

### Q2 2025
- [ ] Kubernetes operator for auto-scaling
- [ ] Real-time streaming enrichment pipeline
- [ ] Advanced ML-based data quality scoring

---

**Built with security and compliance at the core.**
