# Architecture Overview

## Table of Contents
- [System Architecture](#system-architecture)
- [Domain-Driven Design](#domain-driven-design)
- [Security Architecture](#security-architecture)
- [Data Flow](#data-flow)
- [Technology Stack](#technology-stack)

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         External Systems                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  CRM Systems │  │  Enrichment  │  │   Marketing  │  │     SIEM     │    │
│  │  (Salesforce)│  │   Vendors    │  │  Automation  │  │   (Splunk)   │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
└─────────┼──────────────────┼──────────────────┼──────────────────┼──────────┘
          │                  │                  │                  │
          │ mTLS 1.3         │ API Key + HMAC   │ OAuth 2.0        │ Syslog/TLS
          ▼                  ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API Gateway Layer                                 │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  • Rate Limiting (Token Bucket)                                     │    │
│  │  • TLS Termination (mutual TLS for service accounts)                │    │
│  │  • Request Signing Verification                                     │    │
│  │  • IP Whitelisting / GeoIP Filtering                                │    │
│  │  • DDoS Protection (Challenge-Response)                             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Authentication & Authorization                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  • OAuth 2.0 / OIDC Token Validation                                │    │
│  │  • mTLS Certificate Verification                                    │    │
│  │  • Security Context Construction                                    │    │
│  │  • MFA Challenge (if required by policy)                            │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │ SecurityContext
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Application Layer                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │  REST API        │  │  GraphQL API     │  │  gRPC Services   │          │
│  │  Controllers     │  │  Resolvers       │  │  (Internal)      │          │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘          │
│           └────────────────┬─────────────────────────┘                      │
│                            ▼                                                 │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │               Application Services (Use Cases)                      │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │   Contact    │  │  Enrichment  │  │   Sharing    │             │    │
│  │  │   Service    │  │   Service    │  │   Service    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │  Provenance  │  │     DSR      │  │    Policy    │             │    │
│  │  │   Service    │  │   Service    │  │   Service    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Security Kernel (TCB Interface)                          │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │     Auth     │  │     Authz    │  │    Crypto    │             │    │
│  │  │   Service    │  │   Service    │  │   Service    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │    Audit     │  │   Session    │  │   Key Mgmt   │             │    │
│  │  │   Service    │  │    Store     │  │   (HSM/KMS)  │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Domain Layer                                       │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Bounded Contexts (Aggregates)                    │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │   Contact    │  │  Provenance  │  │    Access    │             │    │
│  │  │     Core     │  │    Ledger    │  │  Governance  │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │    Audit     │  │  Enrichment  │  │ Integration  │             │    │
│  │  │    Trail     │  │   Pipeline   │  │   Gateway    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Infrastructure Layer                                  │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │  PostgreSQL  │  │    Kafka     │  │    Redis     │             │    │
│  │  │  (Primary)   │  │ (Event Bus)  │  │   (Cache)    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │     S3       │  │     HSM      │  │    Vault     │             │    │
│  │  │  (Archives)  │  │ (Crypto Ops) │  │  (Secrets)   │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Trusted Operating System (RHEL + SELinux)                  │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  • Mandatory Access Control (MAC)                                   │    │
│  │  • Multi-Level Security (MLS) / Multi-Category Security (MCS)       │    │
│  │  • Process Isolation (cgroups, namespaces)                          │    │
│  │  • Audit Subsystem (auditd with WORM logging)                       │    │
│  │  • Encrypted Storage (dm-crypt, LUKS)                               │    │
│  │  • Secure Boot Chain                                                │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Domain-Driven Design

### Bounded Contexts

The system is organized into six bounded contexts, each owning its domain model and persistence:

#### 1. Contact Core
**Responsibility**: Manage canonical contact identity and enriched attributes

**Key Aggregates**:
- `Contact` (Aggregate Root)
  - `ContactId` (Value Object - ULID)
  - `CanonicalIdentity` (Entity)
  - `EnrichedAttribute[]` (Entity)
  - `ConsentRecord[]` (Entity)

**Invariants**:
- Only one current attribute per type
- All attributes must have valid provenance
- At least one active consent required for processing
- Security label on contact dominates all attribute labels

**Events**:
- `ContactCreated`
- `ContactEnriched`
- `ConsentGranted`
- `ConsentRevoked`

#### 2. Provenance Ledger
**Responsibility**: Immutable record of data origin and transformations

**Key Aggregates**:
- `ProvenanceEvent` (Append-Only Aggregate)
  - `SourceDeclaration` (Value Object)
  - `TransformationChain` (Value Object)
  - `DataFingerprint` (Value Object)
  - `ChainLink` (Value Object)

**Invariants**:
- Events are append-only (never modified or deleted)
- Each event links to previous (hash chain)
- Data fingerprint binds provenance to actual values

**Events**:
- `DataAcquired`
- `DataTransformed`
- `DataMerged`
- `SourceVerified`

#### 3. Access Governance
**Responsibility**: Security policies and sharing tracking

**Key Aggregates**:
- `AccessPolicy` (Aggregate Root)
  - `MandatoryRule[]` (Entity)
  - `DiscretionaryRule[]` (Entity)
- `SharingEvent` (Append-Only Aggregate)
  - `Recipient` (Value Object)
  - `DataReference` (Value Object)

**Invariants**:
- MAC rules override DAC rules
- Sharing events are immutable
- Security clearance required for all operations

**Events**:
- `PolicyCreated`
- `RuleAdded`
- `DataShared`
- `SharingRevoked`

#### 4. Audit Trail
**Responsibility**: Comprehensive, tamper-proof security event logging

**Key Aggregates**:
- `AuditEvent` (Cryptographically-Chained Aggregate)
  - `AuditPrincipal` (Value Object)
  - `AuditResource` (Value Object)
  - `AuditContext` (Value Object)

**Invariants**:
- Events are immutable and signed by HSM
- Each event chains to previous
- All security-relevant operations logged

**Events**:
- `AccessAttempted`
- `PolicyViolation`
- `DataExfiltrationAttempt`

#### 5. Enrichment Pipeline
**Responsibility**: Orchestrate multi-vendor data acquisition

**Key Aggregates**:
- `EnrichmentRequest` (Aggregate Root)
  - `VendorResult[]` (Entity)
  - `MergedAttribute[]` (Value Object)

**Invariants**:
- Vendor results immutable once recorded
- Merge strategy consistently applied
- Provenance created for all enrichments

**Events**:
- `EnrichmentRequested`
- `VendorEnrichmentCompleted`
- `EnrichmentMerged`

#### 6. Integration Gateway
**Responsibility**: Secure external system communication

**Key Aggregates**:
- `Integration` (Aggregate Root)
  - `RateLimitConfig` (Value Object)
  - `RetryPolicy` (Value Object)
  - `IntegrationEndpoint[]` (Entity)

**Invariants**:
- Rate limits enforced before any request
- TLS required for all connections
- Health checks prevent unhealthy integrations

**Events**:
- `IntegrationRegistered`
- `RateLimitExceeded`
- `IntegrationHealthChanged`

### Context Map

```
┌────────────────────────────────────────────────────────────────────┐
│                          Context Map                               │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│   Contact Core ─────[OHS]────> Provenance Ledger                  │
│        │                              │                            │
│        │                              │                            │
│        │                        [ACL] ▼                            │
│        └──────[CF]──────> Access Governance                        │
│                                  │                                 │
│                                  │                                 │
│   Enrichment Pipeline ───[PL]────┘                                 │
│        │                                                           │
│        │                                                           │
│        └──────[CF]──────> Integration Gateway                      │
│                                                                    │
│   All Contexts ─────[OHS]────> Audit Trail                         │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│  OHS = Open Host Service                                          │
│  ACL = Anti-Corruption Layer                                      │
│  CF  = Conformist                                                 │
│  PL  = Published Language                                         │
└────────────────────────────────────────────────────────────────────┘
```

## Security Architecture

### Defense in Depth

The system implements multiple layers of security controls:

| Layer | Controls |
|-------|----------|
| **Network** | Firewall, IDS/IPS, DDoS protection, TLS 1.3, mTLS |
| **Application** | Input validation, output encoding, CSRF protection, rate limiting |
| **Authentication** | OAuth 2.0/OIDC, mTLS, API keys, MFA |
| **Authorization** | RBAC + ABAC, MAC (SELinux), security labels |
| **Data** | AES-256-GCM encryption at rest, field-level encryption, column encryption |
| **Audit** | Comprehensive logging, SIEM integration, tamper-proof trails |
| **OS** | SELinux MAC, process isolation, secure boot, FDE |
| **Physical** | HSM for key storage, air-gapped audit archive |

### Cryptographic Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Cryptographic Key Hierarchy                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────┐         │
│  │          Root Key (HSM Master Key)                    │         │
│  │  • Stored in HSM, never exported                      │         │
│  │  • Used to encrypt Key Encryption Keys (KEKs)         │         │
│  └────────────────────────┬──────────────────────────────┘         │
│                           │                                         │
│           ┌───────────────┼───────────────┐                         │
│           ▼               ▼               ▼                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐               │
│  │  KEK-DATA    │ │ KEK-AUDIT    │ │  KEK-API     │               │
│  │  (Data Enc)  │ │ (Audit Sign) │ │ (API Sign)   │               │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘               │
│         │                │                │                         │
│         ▼                ▼                ▼                         │
│  ┌──────────────────────────────────────────────┐                  │
│  │  Data Encryption Keys (DEKs) - Rotated Daily │                  │
│  │  • Encrypt actual contact data (PII)         │                  │
│  │  • Encrypted by KEK-DATA before storage      │                  │
│  │  • Automatic rotation every 24 hours         │                  │
│  └──────────────────────────────────────────────┘                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Encryption Standards**:
- **Symmetric**: AES-256-GCM (NIST SP 800-38D)
- **Asymmetric**: RSA-4096, ECDSA P-384
- **Hashing**: SHA-384 (NIST FIPS 180-4)
- **Key Derivation**: PBKDF2 (NIST SP 800-132), Argon2id
- **Random**: Hardware RNG from TPM/HSM (NIST SP 800-90B)

## Data Flow

### Contact Enrichment Flow

```
1. API Request                    2. Authentication          3. Authorization
┌──────────────┐                 ┌──────────────┐          ┌──────────────┐
│ POST /contact│───Token────────>│ Verify JWT   │──────────>│ Check Policy │
│ + JWT        │                 │ + mTLS Cert  │          │ + MAC Label  │
└──────────────┘                 └──────────────┘          └──────┬───────┘
                                                                   │
                                                                   ▼
4. Create Contact Aggregate      5. Record Provenance      6. Emit Event
┌──────────────┐                ┌──────────────┐          ┌──────────────┐
│ Contact.create()│────────────>│ Provenance   │────────> │ ContactCreated│
│ • Validate     │              │ .recordOrigin│          │ Event        │
│ • Encrypt PII  │              │ • Hash data  │          └──────┬───────┘
│ • Assign Label │              │ • Chain link │                 │
└────────┬───────┘              └──────────────┘                 │
         │                                                        │
         ▼                                                        ▼
7. Persist to DB                8. Publish to Kafka       9. Trigger Enrichment
┌──────────────┐               ┌──────────────┐          ┌──────────────┐
│ INSERT INTO  │               │ kafka.send(  │          │ Enrichment   │
│ contacts     │               │  topic,event)│          │ Worker starts│
│ • Row encrypt│               └──────────────┘          │ • Call vendors│
│ • RLS check  │                                         │ • Merge results│
└──────────────┘                                         └──────┬───────┘
                                                                │
                                                                ▼
10. Update Contact              11. Record Provenance     12. Audit Event
┌──────────────┐               ┌──────────────┐          ┌──────────────┐
│ contact      │               │ Provenance   │          │ AuditEvent   │
│ .addEnrichment()│──────────>│ .recordXform │────────> │ • Sign w/ HSM│
│ • New attrs  │               │ • Vendor src │          │ • WORM store │
└──────────────┘               └──────────────┘          └──────────────┘
```

### Data Sharing Flow

```
1. Share Request                 2. Authorization Check    3. Legal Basis Check
┌──────────────┐                ┌──────────────┐          ┌──────────────┐
│ POST /share  │────────────────>│ Can share?   │────────> │ Valid consent│
│ + recipient  │                │ • MAC check  │          │ or LI basis? │
│ + purpose    │                │ • Policy eval│          └──────┬───────┘
└──────────────┘                └──────────────┘                 │
                                                                  ▼
4. Create Sharing Event         5. Export Data Package    6. Transmit Securely
┌──────────────┐                ┌──────────────┐          ┌──────────────┐
│ SharingEvent │                │ • Decrypt    │          │ • TLS 1.3    │
│ .create()    │──────────────> │ • Filter flds│────────> │ • Signed pkg │
│ • Snapshot   │                │ • Re-encrypt │          │ • Recipient  │
│ • Legal basis│                │ • Sign       │          │   verif      │
└──────┬───────┘                └──────────────┘          └──────────────┘
       │
       ▼
7. Persist Sharing Event        8. Audit Event            9. Notify SIEM
┌──────────────┐                ┌──────────────┐          ┌──────────────┐
│ INSERT INTO  │                │ AuditEvent   │          │ Forward to   │
│ sharing_events│──────────────>│ (DATA_SHARED)│────────> │ Splunk       │
│ • Immutable  │                │ • HSM signed │          │ • Real-time  │
└──────────────┘                └──────────────┘          └──────────────┘
```

## Technology Stack

### Language Implementations

| Language | Framework | Strengths |
|----------|-----------|-----------|
| **Java** | Spring Boot 3.2+ | Enterprise features, mature ecosystem, JVM optimization |
| **Python** | FastAPI 0.108+ | Rapid development, ML integration, async I/O |
| **Go** | Gin 1.9+ | High performance, low memory, concurrent processing |
| **Rust** | Actix-web 4.4+ | Memory safety, zero-cost abstractions, max security |

### Shared Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Database** | PostgreSQL 15+ | Transactional storage, Row-Level Security |
| **Cache** | Redis 7+ | Session storage, distributed locks |
| **Message Bus** | Kafka 3.6+ | Event sourcing, async communication |
| **Search** | OpenSearch 2.11+ | Full-text search, audit log queries |
| **HSM** | AWS CloudHSM / Luna | Cryptographic operations, key storage |
| **Secrets** | HashiCorp Vault | Dynamic secrets, encryption as a service |
| **Monitoring** | Prometheus + Grafana | Metrics, alerting |
| **Tracing** | Jaeger | Distributed tracing |
| **SIEM** | Splunk / ELK | Security event correlation |

### Operating System

- **RHEL 9.x** (or CentOS Stream 9)
- **SELinux**: Enforcing mode with custom policy
- **Kernel**: 5.14+ with hardening (KASLR, stack protector)
- **Container Runtime**: Podman 4.x (rootless when possible)
- **Orchestration**: Kubernetes 1.28+ with Pod Security Standards

---

**Next**: [Security Architecture](../security/SECURITY.md) | [API Documentation](../api/README.md)
