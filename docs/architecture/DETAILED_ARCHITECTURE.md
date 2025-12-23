# Detailed System Architecture

**Contact Enrichment Platform - Trusted Operating System Edition**

Version: 1.0.0
Last Updated: 2025-01-22

---

## Table of Contents

1. [System Context](#system-context)
2. [Container Architecture](#container-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Architecture](#data-architecture)
5. [Security Architecture](#security-architecture)
6. [Deployment Architecture](#deployment-architecture)
7. [API Architecture](#api-architecture)
8. [Event-Driven Architecture](#event-driven-architecture)

---

## 1. System Context

### 1.1 System Context Diagram

```
                                 Contact Enrichment Platform
                                 (TOS-Compliant Backend)
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                     │
│  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐              │
│  │   CRM        │◄────────┤    API       ├────────►│   SIEM       │              │
│  │  Systems     │  OAuth  │   Gateway    │ Syslog  │  (Splunk)    │              │
│  └──────────────┘         └──────┬───────┘         └──────────────┘              │
│                                   │                                                │
│  ┌──────────────┐                 │                 ┌──────────────┐              │
│  │  Enrichment  │                 │                 │   Marketing  │              │
│  │   Vendors    │◄────────────────┼────────────────►│  Automation  │              │
│  │ (Clearbit)   │   API Keys      │      OAuth      │  (Marketo)   │              │
│  └──────────────┘                 │                 └──────────────┘              │
│                                   │                                                │
│                            ┌──────▼────────┐                                       │
│                            │   Security    │                                       │
│                            │    Kernel     │                                       │
│                            │     (TCB)     │                                       │
│                            └───────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │   Trusted OS (RHEL 9)   │
                         │   SELinux Enforcing     │
                         └─────────────────────────┘
```

### 1.2 External Actors

| Actor | Type | Protocol | Purpose |
|-------|------|----------|---------|
| **CRM Systems** | External Service | HTTPS/OAuth 2.0 | Contact data synchronization |
| **Enrichment Vendors** | External API | HTTPS/API Key | Data enrichment sources |
| **Marketing Automation** | External Service | HTTPS/OAuth 2.0 | Campaign management |
| **SIEM** | Monitoring System | Syslog/TLS | Security event aggregation |
| **Data Subjects** | End Users | HTTPS/Web | DSR (Data Subject Requests) |
| **Administrators** | Internal Users | HTTPS/mTLS | System management |

---

## 2. Container Architecture

### 2.1 Logical Container Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Load Balancer / API Gateway                            │
│                          (Rate Limiting, TLS Termination)                       │
└────────────────────────────────────┬───────────────────────────────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
            ┌───────▼───────┐ ┌─────▼────┐ ┌────────▼─────────┐
            │  Application  │ │   Web    │ │   Background     │
            │   Servers     │ │   API    │ │    Workers       │
            │  (Spring/     │ │ (REST)   │ │ (Enrichment      │
            │   FastAPI/    │ │          │ │  Pipeline)       │
            │   Actix)      │ │          │ │                  │
            └───────┬───────┘ └─────┬────┘ └────────┬─────────┘
                    │               │                │
                    └───────────────┼────────────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    │               │                │
            ┌───────▼────────┐ ┌───▼──────┐ ┌──────▼────────┐
            │   PostgreSQL   │ │  Redis   │ │    Kafka      │
            │   (Primary)    │ │ (Cache)  │ │ (Event Bus)   │
            │                │ │          │ │               │
            └────────────────┘ └──────────┘ └───────────────┘
                    │                              │
            ┌───────▼────────┐             ┌──────▼────────┐
            │   PostgreSQL   │             │  S3/MinIO     │
            │  (Read Replica)│             │  (Archives)   │
            └────────────────┘             └───────────────┘
```

### 2.2 Physical Deployment Topology

```
┌─────────────────── Availability Zone 1 ────────────────────┐
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   App Pod 1  │  │   App Pod 2  │  │  Worker Pod 1│    │
│  │              │  │              │  │              │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                  │             │
│         └─────────────────┼──────────────────┘             │
│                           │                                │
│                  ┌────────▼────────┐                       │
│                  │  PostgreSQL     │                       │
│                  │    Primary      │                       │
│                  └─────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
                           │ (Streaming Replication)
┌─────────────────── Availability Zone 2 ────────────────────┐
│                           │                                │
│                  ┌────────▼────────┐                       │
│                  │  PostgreSQL     │                       │
│                  │   Standby       │                       │
│                  └─────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

### 3.1 Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  REST API Controllers  │  GraphQL Resolvers  │  gRPC Services   │  │
│  │  - ContactController   │  - ContactResolver  │  - Internal RPCs │  │
│  │  - ProvenanceController│                     │                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          APPLICATION LAYER                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Application Services (Use Cases)                                │  │
│  │  - ContactService                                                │  │
│  │  - EnrichmentService                                             │  │
│  │  - ProvenanceService                                             │  │
│  │  - SharingService                                                │  │
│  │  - DSRService (Data Subject Requests)                            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DOMAIN LAYER (Core Business Logic)                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Aggregates                                                      │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │ Contact  │  │Provenance│  │  Access  │  │  Audit   │       │  │
│  │  │   Core   │  │  Event   │  │ Policy   │  │  Event   │       │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │  │
│  │                                                                  │  │
│  │  Value Objects                                                   │  │
│  │  - SecurityLabel  - EncryptedValue  - ProvenanceId             │  │
│  │                                                                  │  │
│  │  Domain Events                                                   │  │
│  │  - ContactCreated  - ContactEnriched  - ConsentRevoked          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          INFRASTRUCTURE LAYER                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Repositories (Data Access)                                      │  │
│  │  - PostgresContactRepository                                     │  │
│  │  - PostgresProvenanceRepository                                  │  │
│  │                                                                  │  │
│  │  Infrastructure Services                                         │  │
│  │  - CryptoService (HSM/KMS integration)                           │  │
│  │  - AuditService (WORM storage)                                   │  │
│  │  - EventBus (Kafka integration)                                  │  │
│  │  - CacheService (Redis)                                          │  │
│  │                                                                  │  │
│  │  External Integrations                                           │  │
│  │  - ClearbitClient  - ZoomInfoClient  - ApolloClient            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          SECURITY KERNEL (TCB)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │ Authent-     │  │ Authoriz-    │  │ Crypto       │                 │
│  │ ication      │  │ ation        │  │ Service      │                 │
│  └──────────────┘  └──────────────┘  └──────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Domain Model - Contact Core

```
┌──────────────────────────────────────────────────────────────────────┐
│                  Contact Aggregate                                   │
├──────────────────────────────────────────────────────────────────────┤
│  Contact (Aggregate Root)                                            │
│  ├─ id: UUID                                                         │
│  ├─ canonicalEmail: EncryptedValue                                   │
│  ├─ canonicalEmailHash: byte[]                                       │
│  ├─ fullName: EncryptedValue?                                        │
│  ├─ securityLabel: SecurityLabel                                     │
│  ├─ enrichedAttributes: List<EnrichedAttribute>                      │
│  ├─ consentRecords: List<ConsentRecord>                              │
│  ├─ createdAt, updatedAt, version                                    │
│  │                                                                    │
│  └─ Invariants:                                                      │
│     • Only one current attribute per type                            │
│     • Security label dominates all attribute labels                  │
│     • At least one active consent required                           │
│     • All attributes have provenance                                 │
├──────────────────────────────────────────────────────────────────────┤
│  EnrichedAttribute (Entity)                                          │
│  ├─ id: UUID                                                         │
│  ├─ attributeType: AttributeType                                     │
│  ├─ encryptedValue: EncryptedValue                                   │
│  ├─ provenanceId: UUID                                               │
│  ├─ confidenceScore: Double [0.0-1.0]                                │
│  ├─ validFrom, validUntil: Instant (Temporal Validity)               │
│  └─ securityLabel: SecurityLabel                                     │
├──────────────────────────────────────────────────────────────────────┤
│  ConsentRecord (Entity)                                              │
│  ├─ id: UUID                                                         │
│  ├─ consentType: ConsentType                                         │
│  ├─ legalBasis: LegalBasis                                           │
│  ├─ purposeCodes: List<String>                                       │
│  ├─ grantedAt, revokedAt?: Instant                                   │
│  └─ evidenceRef: String?                                             │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│              Value Objects                                           │
├──────────────────────────────────────────────────────────────────────┤
│  SecurityLabel (Immutable)                                           │
│  ├─ confidentiality: ConfidentialityLevel                            │
│  ├─ integrity: IntegrityLevel                                        │
│  ├─ compartments: Set<String>                                        │
│  └─ handlingCaveats: Set<String>                                     │
├──────────────────────────────────────────────────────────────────────┤
│  EncryptedValue (Immutable)                                          │
│  ├─ ciphertext: byte[]                                               │
│  ├─ keyId: String                                                    │
│  ├─ algorithm: String                                                │
│  ├─ iv: byte[]?                                                      │
│  └─ authTag: byte[]?                                                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Architecture

### 4.1 Database Schema (ERD)

```
┌─────────────────────────┐
│       contacts          │
├─────────────────────────┤
│ id (PK)                 │
│ canonical_email (BYTEA) │◄────────┐
│ canonical_email_hash    │         │
│ full_name (BYTEA)       │         │
│ security_label          │         │
│ created_at              │         │
│ created_by              │         │
│ version                 │         │
└────────┬────────────────┘         │
         │                          │
         │ 1:N                      │
         ▼                          │
┌─────────────────────────┐         │
│  enriched_attributes    │         │
├─────────────────────────┤         │
│ id (PK)                 │         │
│ contact_id (FK) ────────┘         │
│ attribute_type          │         │
│ encrypted_value (BYTEA) │         │
│ key_id                  │         │
│ provenance_id (FK) ─────┼─────────┐
│ confidence_score        │         │
│ valid_from              │         │
│ valid_until             │         │
│ security_label          │         │
└─────────────────────────┘         │
                                    │
┌─────────────────────────┐         │
│   provenance_events     │         │
├─────────────────────────┤         │
│ sequence_num (PK)       │◄────────┘
│ event_id (UNIQUE)       │
│ event_type              │
│ source_type             │
│ source_identity         │
│ data_subject_id         │
│ attributed_data_hash    │
│ previous_event_hash     │
│ event_hash              │
│ recorded_at             │
└─────────────────────────┘
         ▲
         │ Append-Only
         │ Hash Chain
         ▼

┌─────────────────────────┐
│    sharing_events       │
├─────────────────────────┤
│ id (PK)                 │
│ data_subject_id         │
│ recipient_identity      │
│ sharing_purpose         │
│ legal_basis             │
│ shared_at               │
│ expires_at              │
│ revoked_at              │
└─────────────────────────┘

┌─────────────────────────┐
│     audit_events        │
├─────────────────────────┤
│ sequence_num (PK)       │
│ event_id                │
│ category                │
│ action                  │
│ principal_id            │
│ resource_type           │
│ resource_id             │
│ outcome                 │
│ previous_event_hash     │
│ event_hash              │
│ signature (HSM)         │
│ recorded_at             │
└─────────────────────────┘
```

### 4.2 Data Flow - Contact Creation

```
┌─────────┐     1. POST /contacts     ┌─────────────┐
│  Client │ ─────────────────────────►│ API Gateway │
└─────────┘                            └──────┬──────┘
                                              │ 2. Verify JWT
                                              ▼
                                       ┌─────────────┐
                                       │  Security   │
                                       │   Kernel    │
                                       └──────┬──────┘
                                              │ 3. SecurityContext
                                              ▼
                                       ┌─────────────┐
                                       │  Contact    │
                                       │  Service    │
                                       └──────┬──────┘
                                              │
                        ┌─────────────────────┼─────────────────────┐
                        │ 4. Hash Email       │ 5. Encrypt PII      │
                        ▼                     ▼                     ▼
                 ┌─────────────┐       ┌─────────────┐     ┌─────────────┐
                 │   SHA-256   │       │   Crypto    │     │   Contact   │
                 │   (Email)   │       │   Service   │     │  Aggregate  │
                 └─────────────┘       └─────────────┘     └──────┬──────┘
                                                                   │
                                                                   │ 6. Create Aggregate
                                                                   ▼
                                                            ┌─────────────┐
                                                            │   Contact   │
                                                            │  Repository │
                                                            └──────┬──────┘
                                                                   │
                        ┌──────────────────────────────────────────┼────────────┐
                        │ 7. INSERT                                │            │
                        ▼                                          ▼            ▼
                 ┌─────────────┐                            ┌───────────┐  ┌───────────┐
                 │ PostgreSQL  │                            │   Kafka   │  │   Audit   │
                 │   contacts  │                            │  (Events) │  │    Log    │
                 └─────────────┘                            └───────────┘  └───────────┘
                                                                   │
                                                                   │ 8. ContactCreated Event
                                                                   ▼
                                                            ┌─────────────┐
                                                            │ Enrichment  │
                                                            │   Worker    │
                                                            └─────────────┘
```

---

## 5. Security Architecture

### 5.1 Security Control Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Request Security Flow                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. TLS Handshake                                                   │
│     ├─ Verify client certificate (mTLS for service accounts)       │
│     └─ Establish encrypted channel (TLS 1.3)                        │
│                                                                     │
│  2. Authentication                                                  │
│     ├─ Extract JWT from Authorization header                       │
│     ├─ Verify signature (RSA-4096 / ECDSA P-384)                   │
│     ├─ Validate claims (exp, iss, aud, sub)                        │
│     └─ Construct SecurityPrincipal                                 │
│                                                                     │
│  3. Authorization (MAC + RBAC)                                      │
│     ├─ Extract SecurityClearance from principal                    │
│     ├─ Load resource SecurityLabel                                 │
│     ├─ Check MAC: clearance.dominates(label)?                      │
│     ├─ Evaluate AccessPolicy rules                                 │
│     └─ Decision: ALLOW / DENY                                      │
│                                                                     │
│  4. Input Validation                                                │
│     ├─ Schema validation (Pydantic / Bean Validation)              │
│     ├─ Sanitization (OWASP Encoder)                                │
│     └─ Business rule validation                                    │
│                                                                     │
│  5. Business Logic Execution                                        │
│     ├─ Domain model enforcement                                    │
│     ├─ Cryptographic operations (encrypt/decrypt)                  │
│     └─ Provenance recording                                        │
│                                                                     │
│  6. Audit Logging                                                   │
│     ├─ Create AuditEvent                                           │
│     ├─ Sign with HSM                                               │
│     ├─ Chain to previous event                                     │
│     └─ Write to WORM storage                                       │
│                                                                     │
│  7. Response                                                        │
│     ├─ Output encoding (prevent XSS)                               │
│     ├─ Security headers (CSP, HSTS, etc.)                          │
│     └─ TLS encrypted response                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Cryptographic Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Key Management Hierarchy                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Root Level (HSM/TPM)                                               │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  HSM Master Key (never exported)                              │ │
│  │  - Stored in FIPS 140-2 Level 3 HSM                           │ │
│  │  - Used to derive/wrap all other keys                         │ │
│  └────────────────────────┬──────────────────────────────────────┘ │
│                           │                                         │
│                           ▼                                         │
│  Key Encryption Keys (KEKs)                                         │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  KEK-DATA        │  KEK-AUDIT       │  KEK-API                │ │
│  │  (Data Encrypt)  │  (Audit Sign)    │  (API Sign)             │ │
│  │  AES-256         │  RSA-4096        │  ECDSA P-384            │ │
│  └────────────────────────┬──────────────────────────────────────┘ │
│                           │                                         │
│                           ▼                                         │
│  Data Encryption Keys (DEKs) - Rotated Daily                        │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  DEK-20250122    │  DEK-20250121    │  DEK-20250120           │ │
│  │  (Active)        │  (Decrypt Only)  │  (Decrypt Only)         │ │
│  │  AES-256-GCM     │  AES-256-GCM     │  AES-256-GCM            │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                           │                                         │
│                           ▼                                         │
│  Encrypted Data                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  Ciphertext + IV + AuthTag + KeyID                            │ │
│  │  Stored in PostgreSQL (BYTEA columns)                         │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 SELinux Policy Enforcement

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SELinux Domain Transitions                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐                                                │
│  │     init_t      │  (systemd starts service)                     │
│  └────────┬────────┘                                                │
│           │ domain_auto_trans                                       │
│           ▼                                                         │
│  ┌─────────────────────────────────┐                                │
│  │  contact_enrichment_t           │  Main application domain      │
│  │  • Can read config files        │                               │
│  │  • Can write logs               │                               │
│  │  • Can bind to HTTP ports       │                               │
│  │  • CANNOT directly access DB    │                               │
│  └────────┬───────────┬────────────┘                                │
│           │           │                                             │
│           │           │ domain_auto_trans (when accessing DB)      │
│           │           ▼                                             │
│           │  ┌─────────────────────────┐                            │
│           │  │ contact_enrichment_db_t │  Database access domain   │
│           │  │ • Can connect to        │                           │
│           │  │   postgresql_port_t     │                           │
│           │  │ • Enforces RLS via      │                           │
│           │  │   security labels       │                           │
│           │  └─────────────────────────┘                            │
│           │                                                         │
│           │ domain_auto_trans (for crypto ops)                     │
│           ▼                                                         │
│  ┌─────────────────────────────────┐                                │
│  │ contact_enrichment_crypto_t     │  Crypto operations domain     │
│  │ • Can access HSM device         │                               │
│  │ • Can use /dev/urandom          │                               │
│  │ • CANNOT write to logs          │                               │
│  │   (prevent key leakage)         │                               │
│  └─────────────────────────────────┘                                │
│                                                                     │
│  All domains enforce:                                               │
│  • Bell-LaPadula (no read-up, no write-down)                        │
│  • Biba integrity (no read-down, no write-up)                       │
│  • MCS compartment checks                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. API Architecture

### 6.1 REST API Design

```
Base URL: https://api.contact-enrichment.internal/api/v1

┌────────────────────────────────────────────────────────────────────┐
│  Resource: /contacts                                               │
├────────────────────────────────────────────────────────────────────┤
│  POST   /contacts                   Create contact                │
│  GET    /contacts/{id}              Get contact details            │
│  PUT    /contacts/{id}              Update contact (rare)          │
│  DELETE /contacts/{id}              Delete contact (GDPR)          │
│  GET    /contacts?q=...             Search contacts                │
│                                                                    │
│  POST   /contacts/{id}/enrich       Trigger enrichment             │
│  GET    /contacts/{id}/attributes   Get enriched attributes        │
│  GET    /contacts/{id}/history      Get attribute history          │
│                                                                    │
│  POST   /contacts/{id}/consent      Record consent                 │
│  DELETE /contacts/{id}/consent/{cid}Revoke consent                 │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│  Resource: /provenance                                             │
├────────────────────────────────────────────────────────────────────┤
│  GET    /provenance/{contactId}     Get full provenance chain     │
│  GET    /provenance/verify/{id}     Verify chain integrity         │
│  GET    /provenance/source/{vendor} Query by source                │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│  Resource: /sharing                                                │
├────────────────────────────────────────────────────────────────────┤
│  POST   /sharing                    Record sharing event           │
│  GET    /sharing/contact/{id}       Get sharing history            │
│  PUT    /sharing/{id}/revoke        Revoke sharing                 │
│  GET    /sharing/recipient/{id}     What was shared to recipient   │
│                                                                    │
├────────────────────────────────────────────────────────────────────┤
│  Resource: /dsr (Data Subject Requests)                            │
├────────────────────────────────────────────────────────────────────┤
│  POST   /dsr/access                 GDPR Article 15 request        │
│  POST   /dsr/delete                 Right to be forgotten          │
│  POST   /dsr/rectify                Data rectification             │
│  POST   /dsr/portability            Data portability               │
│  GET    /dsr/{requestId}            Check DSR status               │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### 6.2 API Request/Response Flow

```
┌─────────┐                                                    ┌─────────┐
│ Client  │                                                    │ Server  │
└────┬────┘                                                    └────┬────┘
     │                                                              │
     │ 1. HTTPS Request                                             │
     │────────────────────────────────────────────────────────────► │
     │   POST /api/v1/contacts                                      │
     │   Authorization: Bearer <JWT>                                │
     │   Content-Type: application/json                             │
     │   X-Request-ID: uuid                                         │
     │   X-Purpose: sales_outreach                                  │
     │   {                                                          │
     │     "email": "jane@example.com",                             │
     │     "fullName": "Jane Doe",                                  │
     │     "consentType": "EXPLICIT_OPT_IN",                        │
     │     "legalBasis": "GDPR_ART6_1A",                            │
     │     "purposeCodes": ["sales", "marketing"]                   │
     │   }                                                          │
     │                                                              │
     │                                            2. Authenticate ◄─┤
     │                                            3. Authorize    ◄─┤
     │                                            4. Validate     ◄─┤
     │                                            5. Execute      ◄─┤
     │                                            6. Audit        ◄─┤
     │                                                              │
     │ 7. HTTPS Response                                            │
     │◄──────────────────────────────────────────────────────────── │
     │   HTTP/1.1 201 Created                                       │
     │   Content-Type: application/json                             │
     │   Location: /api/v1/contacts/{id}                            │
     │   X-Request-ID: uuid (same)                                  │
     │   X-RateLimit-Remaining: 99                                  │
     │   {                                                          │
     │     "id": "01HQXYZ...",                                      │
     │     "createdAt": "2025-01-22T10:30:00Z"                      │
     │   }                                                          │
     │                                                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. Deployment Architecture

### 7.1 Kubernetes Deployment

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Namespace: contact-enrichment-prod                                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Ingress (NGINX)                                            │   │
│  │  - TLS termination                                          │   │
│  │  - Rate limiting                                            │   │
│  │  - WAF rules                                                │   │
│  └────────────────────────┬────────────────────────────────────┘   │
│                           │                                         │
│  ┌────────────────────────┴────────────────────────────────────┐   │
│  │  Service: contact-enrichment-api (LoadBalancer)             │   │
│  └────────────────────────┬────────────────────────────────────┘   │
│                           │                                         │
│  ┌────────────────────────┴────────────────────────────────────┐   │
│  │  Deployment: contact-enrichment-app                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │   Pod 1      │  │   Pod 2      │  │   Pod 3      │      │   │
│  │  │  (Java)      │  │  (Java)      │  │  (Java)      │      │   │
│  │  │              │  │              │  │              │      │   │
│  │  │  Resource    │  │  Resource    │  │  Resource    │      │   │
│  │  │  Limits:     │  │  Limits:     │  │  Limits:     │      │   │
│  │  │  CPU: 2      │  │  CPU: 2      │  │  CPU: 2      │      │   │
│  │  │  Mem: 4Gi    │  │  Mem: 4Gi    │  │  Mem: 4Gi    │      │   │
│  │  │              │  │              │  │              │      │   │
│  │  │  Probes:     │  │  Probes:     │  │  Probes:     │      │   │
│  │  │  Liveness    │  │  Liveness    │  │  Liveness    │      │   │
│  │  │  Readiness   │  │  Readiness   │  │  Readiness   │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  │                                                             │   │
│  │  SecurityContext:                                           │   │
│  │  - runAsNonRoot: true                                       │   │
│  │  - seLinuxOptions:                                          │   │
│  │      level: "s0"                                            │   │
│  │      role: "system_r"                                       │   │
│  │      type: "contact_enrichment_t"                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  StatefulSet: postgres-primary                              │   │
│  │  ┌──────────────────────────────────────────────────────┐   │   │
│  │  │  Pod: postgres-0                                     │   │   │
│  │  │  - PVC: 500Gi (SSD)                                  │   │   │
│  │  │  - Backup: pg_basebackup (daily)                     │   │   │
│  │  └──────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Deployment: enrichment-workers                             │   │
│  │  - Replicas: 5                                              │   │
│  │  - Consumes from Kafka                                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ConfigMaps:                                                        │
│  - app-config: Application configuration                           │
│  - selinux-policy: SELinux policy module                           │
│                                                                     │
│  Secrets:                                                           │
│  - db-credentials: PostgreSQL connection string                    │
│  - jwt-keys: JWT signing keys                                      │
│  - vendor-api-keys: Enrichment vendor credentials                  │
│                                                                     │
│  NetworkPolicies:                                                   │
│  - Allow ingress from NGINX only                                   │
│  - Allow egress to PostgreSQL on port 5432                         │
│  - Allow egress to Kafka on port 9092                              │
│  - Deny all other traffic                                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 8. Event-Driven Architecture

### 8.1 Event Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Event-Driven Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Domain Event Emission                                           │
│  ┌────────────────┐                                                 │
│  │   Contact      │                                                 │
│  │   Aggregate    │ ─── emits ───► ContactCreated                   │
│  └────────────────┘                ContactEnriched                  │
│                                    ConsentRevoked                    │
│                                                                     │
│  2. Event Publication (Transactional Outbox Pattern)                │
│  ┌────────────────┐                                                 │
│  │  Repository    │                                                 │
│  │  .save()       │                                                 │
│  │                │                                                 │
│  │  BEGIN TX      │                                                 │
│  │  - INSERT contact                                                │
│  │  - INSERT outbox_event                                           │
│  │  COMMIT        │                                                 │
│  └────────┬───────┘                                                 │
│           │                                                         │
│  3. Event Relay (CDC or Polling)                                    │
│           ▼                                                         │
│  ┌────────────────┐                                                 │
│  │ Event Relay    │ ───► Publishes to Kafka                         │
│  │ (Debezium)     │      Topic: contact.events                      │
│  └────────────────┘                                                 │
│           │                                                         │
│  4. Event Consumption                                                │
│           ▼                                                         │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Kafka Topics                                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │    │
│  │  │  contact.    │  │  provenance. │  │   audit.     │     │    │
│  │  │   events     │  │    events    │  │   events     │     │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │    │
│  └─────────┼──────────────────┼──────────────────┼───────────┘    │
│            │                  │                  │                 │
│            ▼                  ▼                  ▼                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐     │
│  │  Enrichment     │ │  Analytics      │ │  SIEM           │     │
│  │  Worker         │ │  Pipeline       │ │  Forwarder      │     │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘     │
│                                                                     │
│  5. Saga Coordination (Long-Running Transactions)                   │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  EnrichmentSaga:                                            │    │
│  │  1. ContactCreated → Request enrichment from vendors        │    │
│  │  2. VendorEnrichmentCompleted → Merge results               │    │
│  │  3. EnrichmentMerged → Record provenance                    │    │
│  │  4. ProvenanceRecorded → Update contact                     │    │
│  │  5. ContactUpdated → Emit ContactEnriched                   │    │
│  │                                                             │    │
│  │  Compensation:                                               │    │
│  │  - On failure at step 3: Rollback enrichment                │    │
│  │  - On failure at step 4: Log inconsistency + alert          │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Observability

### 9.1 Monitoring Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Observability Architecture                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │  Metrics     │  │   Logs       │  │   Traces     │             │
│  │ (Prometheus) │  │   (ELK)      │  │  (Jaeger)    │             │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │
│         │                 │                  │                     │
│         │                 │                  │                     │
│  ┌──────▼─────────────────▼──────────────────▼───────┐             │
│  │            Application Instrumentation             │             │
│  │  - Micrometer (Java)                               │             │
│  │  - OpenTelemetry                                   │             │
│  │  - Custom business metrics                         │             │
│  └────────────────────────────────────────────────────┘             │
│                                                                     │
│  Key Metrics:                                                       │
│  - API request rate (req/sec)                                       │
│  - API latency (p50, p95, p99)                                      │
│  - Error rate (5xx responses)                                       │
│  - Database connection pool usage                                   │
│  - Enrichment queue depth                                           │
│  - Encryption operations/sec                                        │
│  - Security violations/min                                          │
│                                                                     │
│  Key Logs:                                                          │
│  - Access logs (who accessed what, when)                            │
│  - Security events (auth failures, violations)                      │
│  - Business events (contact created, enriched)                      │
│  - System errors (exceptions, failures)                             │
│                                                                     │
│  Distributed Tracing:                                               │
│  - Trace ID propagated through all services                         │
│  - Spans for: DB queries, cache hits, external API calls           │
│  - Critical path analysis                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Summary

This architecture provides:

✅ **Security by Design**
- MAC enforcement via SELinux
- Cryptographic provenance
- Immutable audit trails
- Defense in depth (8 layers)

✅ **Compliance**
- GDPR Articles 15-22 support
- CCPA consumer rights
- SOC 2 Type II controls
- Complete data lineage

✅ **Scalability**
- Horizontal scaling (stateless app tier)
- Event-driven architecture
- Asynchronous enrichment pipeline
- Read replicas for queries

✅ **Maintainability**
- Domain-Driven Design
- Clean architecture (hexagonal)
- Four language implementations
- Comprehensive testing

**Next Steps**: See [INSTALLATION.md](../setup/INSTALLATION.md) for deployment instructions.

---

**Document Version**: 1.0.0
**Last Updated**: 2025-01-22
**Maintained By**: Platform Architecture Team
