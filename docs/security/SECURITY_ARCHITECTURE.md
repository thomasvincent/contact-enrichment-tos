# Security Architecture - Contact Enrichment Platform

## Executive Summary

This document details the comprehensive security architecture of the Contact Enrichment Platform, designed to meet Trusted Operating System (TOS) requirements with defense-in-depth, mandatory access control (MAC), and cryptographic protection of all PII data.

**Security Posture:**
- **Classification:** Confidential/High Integrity system processing PII
- **Compliance:** GDPR, CCPA, LGPD, SOC 2, ISO 27001
- **Trust Model:** Zero-trust with continuous verification
- **Attack Surface:** Minimal - all interfaces authenticated and authorized

## Table of Contents

1. [Threat Model](#threat-model)
2. [Defense-in-Depth Architecture](#defense-in-depth-architecture)
3. [Mandatory Access Control (MAC)](#mandatory-access-control-mac)
4. [Cryptographic Architecture](#cryptographic-architecture)
5. [Key Management](#key-management)
6. [Audit and Provenance](#audit-and-provenance)
7. [Attack Surface Analysis](#attack-surface-analysis)
8. [Security Controls Mapping](#security-controls-mapping)
9. [Incident Response](#incident-response)

---

## 1. Threat Model

### 1.1 Assets

**Primary Assets:**
- Contact PII (email, name, phone, social profiles)
- Enriched attributes (job title, company, location)
- Cryptographic keys (DEKs, KEKs, signing keys)
- Provenance ledger (data origin and lineage)
- Consent records (GDPR legal basis)
- Audit trail (security events)

**Supporting Assets:**
- Application code and configurations
- Database credentials and connection strings
- API tokens and secrets
- Infrastructure access credentials

### 1.2 Threat Actors

**External Adversaries:**
- **Advanced Persistent Threats (APTs):** Nation-state actors
- **Cybercriminals:** Ransomware, data theft for profit
- **Hacktivists:** Ideologically motivated attackers
- **Competitors:** Corporate espionage

**Internal Threats:**
- **Malicious Insiders:** Privileged users abusing access
- **Negligent Insiders:** Accidental data exposure
- **Compromised Accounts:** Stolen credentials

**Supply Chain:**
- **Third-party Dependencies:** Vulnerable libraries
- **Cloud Providers:** Infrastructure compromise
- **Enrichment Data Vendors:** Malicious data injection

### 1.3 Attack Vectors

1. **Network Attacks:**
   - Man-in-the-middle (MITM) on TLS connections
   - DNS poisoning and hijacking
   - DDoS to disrupt availability

2. **Application Attacks:**
   - SQL injection via unsafe queries
   - XSS and CSRF in web interfaces
   - Deserialization vulnerabilities
   - Authentication bypass
   - Authorization flaws (IDOR, privilege escalation)

3. **Cryptographic Attacks:**
   - Key extraction from memory
   - Side-channel attacks (timing, cache)
   - Downgrade attacks forcing weak algorithms
   - Quantum computer threats (future)

4. **Infrastructure Attacks:**
   - Container escape from Docker/Kubernetes
   - Kernel exploits on RHEL
   - SELinux policy bypass
   - Cloud metadata service exploitation

5. **Social Engineering:**
   - Phishing for credentials
   - Pretexting for data access
   - Insider recruitment

### 1.4 Security Objectives

**Confidentiality:**
- All PII encrypted at rest and in transit
- Access control prevents unauthorized disclosure
- Encryption keys protected in HSM/KMS

**Integrity:**
- Cryptographic signatures prevent tampering
- Audit trail is append-only with hash chains
- Database constraints enforce data validity
- Optimistic locking prevents lost updates

**Availability:**
- Rate limiting prevents resource exhaustion
- Circuit breakers prevent cascade failures
- Multi-region deployment for disaster recovery
- Regular backups with encryption

**Accountability:**
- All operations logged with principal ID
- Audit trail is tamper-evident
- Non-repudiation via digital signatures

---

## 2. Defense-in-Depth Architecture

### 2.1 Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 7: Audit & Monitoring (SIEM, IDS/IPS)                │
├─────────────────────────────────────────────────────────────┤
│ Layer 6: Application Security (Input Validation, RBAC)     │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: MAC Enforcement (SecurityKernel, Bell-LaPadula)   │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Database RLS (PostgreSQL Row-Level Security)      │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Encryption (Field-Level, AES-256-GCM)             │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Network Security (TLS 1.3, mTLS, Firewall)        │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: OS Security (SELinux Enforcing, Kernel Hardening) │
└─────────────────────────────────────────────────────────────┘
```

**Layer 1: Operating System Security**
- **SELinux in Enforcing Mode** (mandatory on startup)
  - 4 security domains: app, database, crypto, audit
  - Type enforcement prevents domain violations
  - MLS/MCS for data classification
- **Kernel Hardening:**
  - ASLR (Address Space Layout Randomization)
  - Stack canaries and NX bit
  - Seccomp filtering system calls
  - Kernel module signing

**Layer 2: Network Security**
- **TLS 1.3 Mutual Authentication:**
  - Client certificates required for service-to-service
  - Certificate pinning prevents MITM
  - Perfect forward secrecy (PFS) with ephemeral keys
- **Network Segmentation:**
  - DMZ for external-facing APIs
  - Private subnet for databases
  - Management network isolated
- **Firewall Rules:**
  - Deny all, allow by exception
  - Egress filtering to prevent data exfiltration

**Layer 3: Encryption**
- **Field-Level Encryption:**
  - All PII encrypted before database write
  - AES-256-GCM authenticated encryption
  - Unique DEK per record
- **Encryption at Rest:**
  - Database volume encryption (LUKS)
  - Backup encryption with separate keys
- **Encryption in Transit:**
  - TLS 1.3 for all network communication
  - Internal service mesh with mTLS

**Layer 4: Database Row-Level Security**
- **PostgreSQL RLS Policies:**
  - SELECT: clearance >= data classification
  - UPDATE/DELETE: clearance >= data classification AND owner
  - INSERT: validated by application
- **Session Variables:**
  - `app.principal_id`: Current user
  - `app.clearance_conf`: Confidentiality clearance
  - `app.clearance_integ`: Integrity clearance
  - `app.compartments`: Need-to-know compartments

**Layer 5: Mandatory Access Control**
- **Bell-LaPadula Model:**
  - No read up: Cannot read higher classification
  - Simple security property enforced
- **Biba Model:**
  - No write down: Cannot write to lower integrity
  - *-integrity property enforced
- **Compartmentalization:**
  - Need-to-know enforced via compartments
  - Chinese Wall for conflict of interest
- **SecurityKernel:**
  - Trusted Computing Base (TCB)
  - All authorization decisions logged
  - Fail-secure on errors

**Layer 6: Application Security**
- **Input Validation:**
  - Whitelist validation for all inputs
  - Bean Validation annotations (Java)
  - Pydantic models (Python)
  - Struct tags (Go)
  - Type system (Rust)
- **Output Encoding:**
  - HTML encoding to prevent XSS
  - JSON encoding to prevent injection
- **CSRF Protection:**
  - Synchronizer tokens for state-changing operations
  - SameSite cookies
- **Rate Limiting:**
  - Token bucket algorithm
  - Per-user and per-IP limits
  - Distributed via Redis

**Layer 7: Audit & Monitoring**
- **SIEM Integration:**
  - All security events sent to SIEM
  - Real-time alerting on suspicious activity
- **Intrusion Detection:**
  - Network-based IDS (Snort/Suricata)
  - Host-based IDS (OSSEC/Wazuh)
- **Anomaly Detection:**
  - ML-based detection of unusual access patterns
  - Behavioral analysis of principals

---

## 3. Mandatory Access Control (MAC)

### 3.1 Bell-LaPadula Model

**Simple Security Property (No Read Up):**
```
Subject can read Object ⟺ Clearance(Subject) ≥ Classification(Object)
```

**Implementation:**
```java
public void authorizeRead(SecurityContext context, SecurityLabel dataLabel) {
    if (!context.getClearance().dominates(dataLabel)) {
        throw new AccessDeniedException("Clearance insufficient");
    }
}
```

**Classification Levels:**
1. **Public** (0): Publicly available data
2. **Internal** (1): Internal use only
3. **Confidential** (2): Sensitive business data, PII
4. **Restricted** (3): Highly sensitive, requires special approval

### 3.2 Biba Integrity Model

***-Integrity Property (No Write Down):**
```
Subject can write Object ⟺ Integrity(Subject) ≥ Integrity(Object)
```

**Implementation:**
```java
public void authorizeWrite(SecurityContext context, SecurityLabel dataLabel) {
    if (dataLabel.getIntegrity().ordinal() > context.getClearance().getIntegrity().ordinal()) {
        throw new AccessDeniedException("Cannot write to higher integrity");
    }
    authorizeRead(context, dataLabel); // Must also satisfy Bell-LaPadula
}
```

**Integrity Levels:**
1. **Low** (0): Untrusted external data
2. **Medium** (1): Validated external data
3. **High** (2): Internal trusted data
4. **Critical** (3): System-critical data

### 3.3 Compartmentalization

**Need-to-Know Enforcement:**
```
Subject can access Object ⟺ Compartments(Subject) ⊇ Compartments(Object)
```

**Compartment Examples:**
- **PII**: Personal identifiable information
- **FINANCIAL**: Financial data
- **HEALTH**: Health records
- **EU**: Data subject to GDPR
- **US**: Data subject to CCPA

### 3.4 Caveats

Special handling requirements:
- **ORIGINATOR_CONTROLLED**: Only data originator can access
- **NOFORN**: No foreign nationals
- **RELEASABLE_TO_X**: Releasable only to specific entities

### 3.5 Security Label Structure

```java
public class SecurityLabel {
    ConfidentialityLevel confidentiality;  // Bell-LaPadula
    IntegrityLevel integrity;              // Biba
    Set<String> compartments;              // Need-to-know
    Set<String> caveats;                   // Special restrictions

    public boolean dominates(SecurityLabel other) {
        return this.confidentiality.ordinal() >= other.confidentiality.ordinal()
            && this.integrity.ordinal() >= other.integrity.ordinal()
            && this.compartments.containsAll(other.compartments);
    }
}
```

---

## 4. Cryptographic Architecture

### 4.1 Encryption Standards

**Algorithms (FIPS 140-2 Compliant):**
- **Symmetric:** AES-256-GCM (authenticated encryption)
- **Asymmetric:** RSA-4096, ECDSA P-384
- **Hashing:** SHA-256, SHA-512
- **Key Derivation:** PBKDF2, HKDF
- **MAC:** HMAC-SHA256

**Why AES-256-GCM:**
- Authenticated encryption (confidentiality + integrity)
- Resistant to timing attacks (constant-time)
- Hardware acceleration (AES-NI instructions)
- NIST approved, FIPS 140-2 validated

### 4.2 Envelope Encryption

```
┌─────────────────────────────────────────────┐
│ Root Key (HSM)                              │
│   ↓ derives                                 │
│ Customer Master Key (CMK) in KMS            │
│   ↓ encrypts                                │
│ Key Encryption Key (KEK) per purpose        │
│   ↓ encrypts                                │
│ Data Encryption Key (DEK) per record        │
│   ↓ encrypts                                │
│ Plaintext PII                               │
└─────────────────────────────────────────────┘
```

**Benefits:**
1. **Key Rotation:** Rotate KEK without re-encrypting data
2. **Performance:** DEKs cached in application memory
3. **Separation:** Different KEKs for different purposes
4. **Auditability:** KMS logs all key operations

### 4.3 Key Hierarchy

**Root Key:**
- Stored in Hardware Security Module (HSM)
- FIPS 140-2 Level 3 certified
- Never leaves HSM
- Used only to encrypt CMKs

**Customer Master Keys (CMKs):**
- Stored in AWS KMS / Azure Key Vault / HashiCorp Vault
- One CMK per environment (dev, staging, prod)
- Automatic rotation every 365 days
- CloudTrail logs all operations

**Key Encryption Keys (KEKs):**
- Derived from CMK for specific purposes
- Purposes: email, name, phone, ssn, financial
- Cached in application memory (encrypted at rest)
- Rotation triggers DEK re-encryption

**Data Encryption Keys (DEKs):**
- Generated per encryption operation
- 256-bit random from CSPRNG
- Never stored (only encrypted DEK stored)
- Destroyed after use

### 4.4 Nonce Management

**Requirements:**
- Unique per encryption (never reused with same key)
- 96 bits for GCM (recommended)
- Cryptographically random (not sequential)

**Implementation:**
```java
byte[] nonce = new byte[12]; // 96 bits
secureRandom.nextBytes(nonce);
```

**Collision Probability:**
- After 2^32 encryptions with same key: ~0.0001%
- Mitigation: Rotate DEK frequently (per record)

### 4.5 Authentication Tag

**GCM Authentication Tag:**
- 128 bits appended to ciphertext
- Verifies integrity and authenticity
- Prevents tampering and forgery

**Storage:**
```sql
CREATE TABLE contacts (
    id UUID PRIMARY KEY,
    canonical_email_ciphertext BYTEA NOT NULL,
    canonical_email_auth_tag BYTEA NOT NULL,  -- 16 bytes
    canonical_email_iv BYTEA NOT NULL,        -- 12 bytes
    canonical_email_key_id VARCHAR(256) NOT NULL
);
```

---

## 5. Key Management

### 5.1 Key Lifecycle

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│          │     │          │     │          │     │          │     │          │
│ Generate │────▶│  Active  │────▶│ Rotated  │────▶│ Retired  │────▶│ Destroyed│
│          │     │          │     │          │     │          │     │          │
└──────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘
    Day 0           Day 1-365       Day 366-730      Day 731+          Day 2555+
```

**Generate:**
- Keys created in HSM
- Cryptographically random
- Metadata recorded (ID, purpose, created_at)

**Active:**
- Used for encryption and decryption
- Monitored for usage patterns
- Backed up to secure location

**Rotated:**
- New key created, old key deprecated
- Old key still used for decryption only
- Re-encryption of data begins

**Retired:**
- No longer used for decryption
- Kept for audit and compliance
- Access restricted to security team

**Destroyed:**
- Securely deleted from all systems
- HSM wipe with overwrite
- Destruction logged and audited

### 5.2 Key Rotation

**Automatic Rotation (CMKs):**
- AWS KMS rotates annually
- Previous versions retained for decryption
- Zero downtime rotation

**Manual Rotation (KEKs):**
- Triggered by security team
- Reasons: suspected compromise, policy change, compliance
- Process:
  1. Generate new KEK
  2. Encrypt all DEKs with new KEK
  3. Update key reference in database
  4. Mark old KEK as retired

**DEK Rotation:**
- New DEK per encryption operation
- No rotation needed (single-use)

### 5.3 Key Access Control

**HSM Access:**
- Quorum required (M of N keys)
- Hardware authentication required
- All access logged to SIEM

**KMS Access:**
- IAM policies restrict to application service account
- MFA required for admin operations
- CloudTrail logs all API calls

**Application Access:**
- Service identity via mTLS client certificate
- Least privilege - only access needed KEKs
- Temporary credentials (STS)

---

## 6. Audit and Provenance

### 6.1 Cryptographic Audit Trail

**Append-Only Log with Hash Chain:**
```
Event[n] = {
    timestamp,
    principal_id,
    operation,
    resource_id,
    result,
    prev_hash,
    signature
}

hash[n] = SHA256(Event[n] || hash[n-1])
signature[n] = Sign(hash[n], audit_private_key)
```

**Tamper Detection:**
- Any modification breaks hash chain
- Signature verification fails
- Alerts triggered immediately

### 6.2 Provenance Tracking

**Data Lineage:**
```
Contact → EnrichedAttribute → ProvenanceEvent
         ↓                    ↓
    confidence_score      {source, method, timestamp, signature}
```

**Provenance Fields:**
- **Source:** API, enrichment vendor, user input
- **Method:** Algorithm used for enrichment
- **Timestamp:** When data was obtained
- **Confidence:** Accuracy score (0.0-1.0)
- **Signature:** Digital signature from source

### 6.3 Audit Event Types

**Security Events:**
- Authentication success/failure
- Authorization grant/deny
- Encryption/decryption operations
- Key access

**Data Events:**
- Contact created/updated/deleted
- Enrichment added
- Consent granted/revoked
- Data shared with third party

**Administrative Events:**
- Configuration changes
- User provisioning
- Role assignments
- Security policy updates

### 6.4 SIEM Integration

**Log Format (JSON):**
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "request_id": "uuid",
  "principal_id": "uuid",
  "operation": "READ_CONTACT",
  "resource_id": "uuid",
  "clearance": {"conf": "CONFIDENTIAL", "integ": "HIGH"},
  "data_label": {"conf": "INTERNAL", "integ": "MEDIUM"},
  "result": "GRANTED",
  "duration_ms": 45
}
```

**Real-Time Alerting:**
- Authorization denials exceeding threshold
- Unusual access patterns (time, location, volume)
- Encryption failures
- Key access anomalies

---

## 7. Attack Surface Analysis

### 7.1 External Attack Surface

**Exposed Interfaces:**
1. **REST API (HTTPS):**
   - Authentication: JWT bearer tokens
   - Rate limiting: 100 req/min per user
   - Input validation: Strict whitelist
   - Attack vectors: Injection, broken auth, IDOR

2. **Health Check Endpoint:**
   - Unauthenticated (by design)
   - Returns only boolean status
   - No sensitive information leaked

**Mitigations:**
- Web Application Firewall (WAF)
- DDoS protection (CloudFlare, AWS Shield)
- API gateway with rate limiting
- Input validation at every layer

### 7.2 Internal Attack Surface

**Service-to-Service:**
- **Database:** PostgreSQL port 5432
  - mTLS client certificates
  - Connection pooling (max 20 connections)
  - Prepared statements (no SQL injection)

- **Redis:** Port 6379
  - TLS encryption
  - AUTH password required
  - ACLs restrict commands

- **Kafka:** Port 9092
  - SASL/SCRAM authentication
  - TLS encryption
  - ACLs per topic

**Mitigations:**
- Network segmentation (private subnets)
- Security groups allow only required ports
- Mutual TLS for authentication
- Least privilege service accounts

### 7.3 Supply Chain

**Dependencies:**
- **Automated Scanning:** Snyk, Dependabot, Trivy
- **Vulnerability Threshold:** Block critical/high CVEs
- **Software Bill of Materials (SBOM):** Generated on build
- **License Compliance:** Approved open-source licenses only

**Container Images:**
- **Base Image:** Distroless or minimal Alpine
- **Image Scanning:** Trivy, Clair, Anchore
- **Image Signing:** Cosign with Sigstore
- **Registry:** Private ECR/ACR with access control

---

## 8. Security Controls Mapping

### 8.1 NIST Cybersecurity Framework

| Control ID | Control Name | Implementation |
|------------|--------------|----------------|
| ID.AM-1 | Asset Management | CMDB with all assets cataloged |
| ID.RA-1 | Risk Assessment | Annual threat modeling, STRIDE |
| PR.AC-1 | Identity Management | JWT with OAuth 2.0, MFA required |
| PR.AC-4 | Access Control | RBAC + MAC (Bell-LaPadula, Biba) |
| PR.DS-1 | Data at Rest | AES-256-GCM field-level encryption |
| PR.DS-2 | Data in Transit | TLS 1.3 with mTLS |
| PR.PT-1 | Audit Logging | Cryptographic audit trail, SIEM |
| DE.CM-1 | Network Monitoring | IDS/IPS with anomaly detection |
| DE.AE-2 | Incident Analysis | SOAR playbooks, threat intelligence |
| RS.RP-1 | Incident Response | IR plan tested quarterly |

### 8.2 GDPR Compliance

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| Art. 5 | Data Minimization | Only necessary PII collected |
| Art. 6 | Legal Basis | Consent recorded with proof |
| Art. 13 | Transparency | Privacy notice at collection |
| Art. 15 | Right of Access | GET /contacts/{id} API |
| Art. 16 | Right to Rectification | PUT /contacts/{id} API |
| Art. 17 | Right to Erasure | DELETE /contacts/{id} API |
| Art. 18 | Right to Restriction | Contact.freeze() method |
| Art. 20 | Right to Portability | Export to JSON/CSV |
| Art. 25 | Privacy by Design | MAC, encryption, pseudonymization |
| Art. 30 | Processing Records | Provenance ledger tracks all processing |
| Art. 32 | Security Measures | Encryption, access control, audit trail |
| Art. 33 | Breach Notification | Automated alerting, 72-hour SLA |

---

## 9. Incident Response

### 9.1 Incident Classification

**Severity Levels:**
1. **Critical:** Active data breach, ransomware, HSM compromise
2. **High:** Attempted breach, privilege escalation, key exposure
3. **Medium:** Brute force attack, DDoS, malware detection
4. **Low:** Failed authentication, policy violation, anomaly

### 9.2 Response Procedures

**Critical Incident (Data Breach):**
1. **Detect:** SIEM alert triggers
2. **Contain:** Isolate affected systems, revoke credentials
3. **Eradicate:** Remove attacker access, patch vulnerabilities
4. **Recover:** Restore from clean backups, re-key cryptography
5. **Lessons Learned:** Post-incident review, update procedures

**Notification:**
- GDPR: 72 hours to supervisory authority
- CCPA: Without unreasonable delay
- Affected individuals: Per legal requirements

### 9.3 Forensics

**Evidence Collection:**
- Immutable audit trail preserved
- Database snapshots captured
- Network packet captures (if available)
- Memory dumps from compromised systems

**Chain of Custody:**
- All evidence cryptographically hashed
- Access logged with timestamps
- Transfer records maintained

---

## Appendix A: Cryptographic Algorithms

### Approved Algorithms

**Symmetric Encryption:**
- AES-256-GCM (primary)
- ChaCha20-Poly1305 (alternative)

**Asymmetric Encryption:**
- RSA-4096
- ECDH P-384

**Digital Signatures:**
- ECDSA P-384
- EdDSA (Ed25519)

**Hashing:**
- SHA-256 (general purpose)
- SHA-512 (signatures)
- Argon2id (password hashing)

**Key Derivation:**
- HKDF-SHA256
- PBKDF2 (legacy support)

### Prohibited Algorithms

- DES, 3DES (broken)
- RC4 (biased)
- MD5, SHA-1 (collision attacks)
- RSA < 2048 bits (factorable)

---

## Appendix B: Security Checklist

**Pre-Deployment:**
- [ ] SELinux in enforcing mode
- [ ] TLS 1.3 enabled, TLS < 1.2 disabled
- [ ] All secrets in KMS/Vault (not in code)
- [ ] Database RLS policies applied
- [ ] Security kernel enforcing MAC
- [ ] Rate limiting configured
- [ ] SIEM integration tested
- [ ] Incident response plan documented
- [ ] Vulnerability scan passed (no critical/high)
- [ ] Penetration test completed

**Runtime:**
- [ ] All operations audited
- [ ] Encryption keys rotated on schedule
- [ ] Access logs reviewed daily
- [ ] Alerts configured and tested
- [ ] Backups encrypted and tested
- [ ] Dependency updates applied weekly
- [ ] Security patches applied within 7 days

---

## Document Control

**Version:** 1.0
**Last Updated:** 2024-01-01
**Classification:** Internal
**Owner:** Security Team
**Review Frequency:** Quarterly
