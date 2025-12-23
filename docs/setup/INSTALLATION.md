# Installation Guide

## Table of Contents
- [Prerequisites](#prerequisites)
- [System Requirements](#system-requirements)
- [Installation Steps](#installation-steps)
- [SELinux Configuration](#selinux-configuration)
- [Database Setup](#database-setup)
- [Application Deployment](#application-deployment)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Operating System
- **Red Hat Enterprise Linux 9.x** (or CentOS Stream 9 / Rocky Linux 9)
- SELinux **enforcing** mode (required for TOS compliance)
- Minimum 16GB RAM, 4 vCPUs, 100GB storage

### Required Packages
```bash
# Update system
sudo dnf update -y

# Install base requirements
sudo dnf install -y \
    policycoreutils-python-utils \
    selinux-policy-devel \
    postgresql15-server \
    postgresql15-contrib \
    redis \
    java-21-openjdk-devel \
    maven \
    git \
    curl \
    wget \
    unzip

# Verify SELinux is enforcing
sestatus
# Should show: Current mode: enforcing
```

### Network Requirements
- Outbound HTTPS (443) for vendor API calls
- Inbound HTTPS (8443) for API serving
- PostgreSQL (5432) - internal only
- Redis (6379) - internal only

## System Requirements

### Hardware (Production)
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe |
| Network | 1 Gbps | 10 Gbps |

### Software Versions
| Component | Version |
|-----------|---------|
| RHEL | 9.2+ |
| PostgreSQL | 15.5+ |
| Redis | 7.0+ |
| Java (for Java impl) | 21 LTS |
| Python (for Python impl) | 3.11+ |
| Go (for Go impl) | 1.21+ |
| Rust (for Rust impl) | 1.75+ |

## Installation Steps

### Step 1: Clone Repository

```bash
# Create application user
sudo useradd -r -m -d /opt/contact-enrichment -s /bin/bash contact-enrichment

# Clone repository
sudo -u contact-enrichment git clone https://github.com/yourorg/contact-enrichment-tos.git \
    /opt/contact-enrichment/app

cd /opt/contact-enrichment/app
```

### Step 2: Choose Implementation

```bash
# For Java implementation
git checkout impl/java
cd implementations/java

# For Python implementation
git checkout impl/python
cd implementations/python

# For Go implementation
git checkout impl/go
cd implementations/go

# For Rust implementation
git checkout impl/rust
cd implementations/rust
```

### Step 3: Configure Secrets

```bash
# Create secrets directory (restricted permissions)
sudo mkdir -p /etc/contact-enrichment/secrets
sudo chown contact-enrichment:contact-enrichment /etc/contact-enrichment/secrets
sudo chmod 700 /etc/contact-enrichment/secrets

# Generate database password
DB_PASSWORD=$(openssl rand -base64 32)
echo "$DB_PASSWORD" | sudo tee /etc/contact-enrichment/secrets/db_password > /dev/null
sudo chmod 400 /etc/contact-enrichment/secrets/db_password

# Generate JWT signing key
JWT_SECRET=$(openssl rand -base64 64)
echo "$JWT_SECRET" | sudo tee /etc/contact-enrichment/secrets/jwt_secret > /dev/null
sudo chmod 400 /etc/contact-enrichment/secrets/jwt_secret

# Generate encryption master key (for envelope encryption)
MASTER_KEY=$(openssl rand -base64 32)
echo "$MASTER_KEY" | sudo tee /etc/contact-enrichment/secrets/master_key > /dev/null
sudo chmod 400 /etc/contact-enrichment/secrets/master_key
```

### Step 4: Install SELinux Policy

```bash
# Compile and install SELinux policy
cd /opt/contact-enrichment/app
sudo ./scripts/selinux/install-policy.sh

# Verify policy is loaded
sudo semodule -l | grep contact_enrichment
# Should show: contact_enrichment    1.0.0
```

## SELinux Configuration

### Install Custom Policy

The installation script performs the following:

```bash
#!/bin/bash
# scripts/selinux/install-policy.sh

set -euo pipefail

echo "[INFO] Compiling SELinux policy..."
cd scripts/selinux

# Compile policy module
checkmodule -M -m -o contact_enrichment.mod contact_enrichment.te

# Create policy package
semodule_package -o contact_enrichment.pp -m contact_enrichment.mod

# Install policy
echo "[INFO] Installing SELinux policy..."
sudo semodule -i contact_enrichment.pp

# Verify installation
echo "[INFO] Verifying policy installation..."
semodule -l | grep contact_enrichment

# Set file contexts
echo "[INFO] Setting file contexts..."
sudo semanage fcontext -a -t contact_enrichment_exec_t \
    '/usr/local/bin/contact-enrichment'
sudo semanage fcontext -a -t contact_enrichment_conf_t \
    '/etc/contact-enrichment(/.*)?'
sudo semanage fcontext -a -t contact_enrichment_log_t \
    '/var/log/contact-enrichment(/.*)?'
sudo semanage fcontext -a -t contact_enrichment_var_t \
    '/var/lib/contact-enrichment(/.*)?'

# Create directories and restore contexts
sudo mkdir -p /etc/contact-enrichment \
              /var/log/contact-enrichment \
              /var/lib/contact-enrichment

sudo restorecon -Rv /etc/contact-enrichment \
                     /var/log/contact-enrichment \
                     /var/lib/contact-enrichment

echo "[SUCCESS] SELinux policy installed successfully"
```

### Verify SELinux Context

```bash
# Check file contexts
ls -lZ /etc/contact-enrichment
ls -lZ /var/log/contact-enrichment

# Should show contact_enrichment_*_t contexts

# Test policy (should deny)
sudo -u contact-enrichment cat /etc/shadow
# Should fail with SELinux denial

# Check audit log for denials
sudo ausearch -m avc -ts recent | grep contact_enrichment
```

## Database Setup

### PostgreSQL Installation

```bash
# Initialize PostgreSQL
sudo postgresql-setup --initdb

# Enable and start PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Set postgres user password
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$(cat /etc/contact-enrichment/secrets/db_password)';"

# Configure pg_hba.conf for local connections
sudo tee -a /var/lib/pgsql/data/pg_hba.conf > /dev/null <<EOF
# Contact Enrichment Platform
host    contact_enrichment    contact_enrichment    127.0.0.1/32    scram-sha-256
host    contact_enrichment    contact_enrichment    ::1/128         scram-sha-256
EOF

# Configure postgresql.conf for security
sudo tee -a /var/lib/pgsql/data/postgresql.conf > /dev/null <<EOF
# Security Hardening
ssl = on
password_encryption = scram-sha-256
row_security = on
shared_preload_libraries = 'pg_stat_statements,pgaudit,pgcrypto'

# Performance
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 2GB
max_wal_size = 8GB

# Logging for audit
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'ddl'
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%m [%p] %q%u@%d '
EOF

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### Create Database and Schema

```bash
# Create database user and database
sudo -u postgres psql <<EOF
CREATE USER contact_enrichment WITH PASSWORD '$(cat /etc/contact-enrichment/secrets/db_password)';
CREATE DATABASE contact_enrichment OWNER contact_enrichment;
\c contact_enrichment
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL PRIVILEGES ON DATABASE contact_enrichment TO contact_enrichment;
EOF

# Run database migrations (example for Java/Flyway)
cd /opt/contact-enrichment/app/implementations/java
DB_URL="jdbc:postgresql://localhost:5432/contact_enrichment" \
DB_USER="contact_enrichment" \
DB_PASSWORD="$(cat /etc/contact-enrichment/secrets/db_password)" \
./mvnw flyway:migrate
```

### Database Schema (Initial Migration)

See `implementations/java/src/main/resources/db/migration/V1__initial_schema.sql`:

```sql
-- V1__initial_schema.sql
-- Initial database schema for Contact Enrichment Platform

-- Security labels type (for MAC enforcement)
CREATE TYPE confidentiality_level AS ENUM ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED');
CREATE TYPE integrity_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- Contacts table
CREATE TABLE contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Encrypted PII
    canonical_email BYTEA NOT NULL,
    canonical_email_hash BYTEA NOT NULL UNIQUE, -- For lookups without decryption
    full_name BYTEA,

    -- Security label for MAC
    security_label_confidentiality confidentiality_level NOT NULL DEFAULT 'INTERNAL',
    security_label_integrity integrity_level NOT NULL DEFAULT 'MEDIUM',

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1,

    CONSTRAINT valid_email_hash CHECK (length(canonical_email_hash) = 32)
);

-- Row-Level Security (RLS) for MAC enforcement
ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see rows at or below their clearance level
CREATE POLICY contact_mac_policy ON contacts
    FOR SELECT
    USING (
        security_label_confidentiality <= current_setting('app.user_clearance_confidentiality')::confidentiality_level
        AND security_label_integrity <= current_setting('app.user_clearance_integrity')::integrity_level
    );

-- Enriched attributes table (temporal data)
CREATE TABLE enriched_attributes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,

    attribute_type VARCHAR(50) NOT NULL,
    encrypted_value BYTEA NOT NULL,

    -- Encryption metadata
    key_id VARCHAR(256) NOT NULL,
    algorithm VARCHAR(64) NOT NULL DEFAULT 'AES-256-GCM',
    iv BYTEA,
    auth_tag BYTEA,

    -- Provenance linkage
    provenance_id UUID NOT NULL,

    -- Confidence and temporal validity
    confidence_score DECIMAL(3,2) CHECK (confidence_score BETWEEN 0 AND 1),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,

    -- Security label
    security_label_confidentiality confidentiality_level NOT NULL,
    security_label_integrity integrity_level NOT NULL,

    -- Prevent overlapping validity periods for same attribute type
    EXCLUDE USING gist (
        contact_id WITH =,
        attribute_type WITH =,
        tstzrange(valid_from, valid_until, '[)') WITH &&
    )
);

CREATE INDEX idx_enriched_attrs_contact ON enriched_attributes(contact_id);
CREATE INDEX idx_enriched_attrs_provenance ON enriched_attributes(provenance_id);
CREATE INDEX idx_enriched_attrs_current ON enriched_attributes(contact_id, attribute_type)
    WHERE valid_until IS NULL;

-- Provenance ledger (append-only)
CREATE TABLE provenance_events (
    sequence_num BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_type VARCHAR(50) NOT NULL,

    -- Source attestation
    source_type VARCHAR(50),
    source_identity TEXT,
    source_credential_hash BYTEA,
    acquisition_method VARCHAR(50),

    -- Data binding
    data_subject_id UUID NOT NULL,
    attributed_data_hash BYTEA NOT NULL,

    -- Transformation lineage
    parent_provenance_ids UUID[],
    transformation_spec JSONB,

    -- Cryptographic chain
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    previous_event_hash BYTEA NOT NULL,
    event_hash BYTEA NOT NULL,

    -- Merkle anchoring
    merkle_batch_id UUID,
    merkle_proof BYTEA
);

-- Prevent UPDATE/DELETE (append-only)
CREATE RULE provenance_immutable AS ON UPDATE TO provenance_events DO INSTEAD NOTHING;
CREATE RULE provenance_no_delete AS ON DELETE TO provenance_events DO INSTEAD NOTHING;

CREATE INDEX idx_provenance_subject ON provenance_events(data_subject_id, recorded_at DESC);
CREATE INDEX idx_provenance_source ON provenance_events(source_identity, source_type);

-- Sharing events (immutable audit trail)
CREATE TABLE sharing_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- What was shared
    data_subject_id UUID NOT NULL,
    data_snapshot_hash BYTEA NOT NULL,
    shared_fields JSONB NOT NULL,

    -- Who shared
    shared_by_principal_id UUID NOT NULL,
    shared_by_clearance_confidentiality confidentiality_level NOT NULL,

    -- To whom
    recipient_type VARCHAR(50) NOT NULL,
    recipient_identity TEXT NOT NULL,
    recipient_organization TEXT,

    -- Why
    sharing_purpose VARCHAR(100) NOT NULL,
    legal_basis VARCHAR(50) NOT NULL,
    consent_reference UUID,

    -- When and how long
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Audit linkage
    audit_event_id UUID NOT NULL
);

CREATE INDEX idx_sharing_by_subject ON sharing_events(data_subject_id, shared_at DESC);
CREATE INDEX idx_sharing_by_recipient ON sharing_events(recipient_identity, shared_at DESC);

-- Audit events (cryptographically chained, WORM storage)
CREATE TABLE audit_events (
    sequence_num BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,

    -- Event classification
    category VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,

    -- Principal (who)
    principal_id UUID NOT NULL,
    principal_authentication_method VARCHAR(50) NOT NULL,
    principal_session_id UUID NOT NULL,
    principal_source_ip INET,

    -- Resource (what)
    resource_type VARCHAR(100) NOT NULL,
    resource_id TEXT NOT NULL,

    -- Context (when, where)
    request_id UUID NOT NULL,
    trusted_path BOOLEAN NOT NULL DEFAULT FALSE,
    request_timestamp TIMESTAMPTZ NOT NULL,
    processing_node VARCHAR(256) NOT NULL,

    -- Outcome
    outcome VARCHAR(20) NOT NULL,
    outcome_details TEXT,

    -- Cryptographic integrity
    previous_event_hash BYTEA NOT NULL,
    event_hash BYTEA NOT NULL,
    signature BYTEA,
    signing_key_id VARCHAR(256),

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent modification (WORM)
CREATE RULE audit_immutable AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_events DO INSTEAD NOTHING;

CREATE INDEX idx_audit_principal ON audit_events(principal_id, recorded_at DESC);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id, recorded_at DESC);
CREATE INDEX idx_audit_request ON audit_events(request_id);
CREATE INDEX idx_audit_category ON audit_events(category, action, recorded_at DESC);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON contacts TO contact_enrichment;
GRANT SELECT, INSERT, UPDATE ON enriched_attributes TO contact_enrichment;
GRANT SELECT, INSERT ON provenance_events TO contact_enrichment;
GRANT SELECT, INSERT ON sharing_events TO contact_enrichment;
GRANT SELECT, INSERT ON audit_events TO contact_enrichment;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO contact_enrichment;
```

## Application Deployment

### Java Implementation

```bash
cd /opt/contact-enrichment/app/implementations/java

# Build application
./mvnw clean package -DskipTests

# Create systemd service
sudo tee /etc/systemd/system/contact-enrichment.service > /dev/null <<EOF
[Unit]
Description=Contact Enrichment Platform
After=network.target postgresql.service

[Service]
Type=simple
User=contact-enrichment
Group=contact-enrichment

WorkingDirectory=/opt/contact-enrichment/app/implementations/java
ExecStart=/usr/bin/java \\
    -Xms2g -Xmx4g \\
    -XX:+UseG1GC \\
    -XX:+UseStringDeduplication \\
    -Djava.security.egd=file:/dev/urandom \\
    -jar target/contact-enrichment-tos-1.0.0.jar

Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/contact-enrichment /var/lib/contact-enrichment

# SELinux
SELinuxContext=system_u:system_r:contact_enrichment_t:s0

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
sudo systemctl daemon-reload
sudo systemctl enable contact-enrichment
sudo systemctl start contact-enrichment

# Check status
sudo systemctl status contact-enrichment
```

## Verification

### Health Checks

```bash
# Application health
curl -k https://localhost:8443/api/v1/health
# Expected: {"status":"UP"}

# Database connectivity
curl -k https://localhost:8443/api/v1/ready
# Expected: {"status":"READY","database":"UP"}

# Metrics
curl -k https://localhost:8443/metrics
# Should return Prometheus-format metrics
```

### SELinux Verification

```bash
# Check for denials
sudo ausearch -m avc -ts recent | grep denied
# Should be empty or only expected denials

# Verify application is running in correct context
ps auxZ | grep contact-enrichment
# Should show: system_u:system_r:contact_enrichment_t:s0
```

### Security Tests

```bash
# Run security test suite
cd /opt/contact-enrichment/app/implementations/java
./mvnw verify -P security-tests

# Check for vulnerabilities
./mvnw org.owasp:dependency-check-maven:check
```

## Troubleshooting

### Common Issues

#### SELinux Denials

```bash
# View recent denials
sudo ausearch -m avc -ts recent

# Generate allow rules (ONLY for development)
sudo ausearch -m avc -ts recent | audit2allow -M contact_enrichment_local
# Review generated rules before applying!

# Apply (if safe)
sudo semodule -i contact_enrichment_local.pp
```

#### Database Connection Issues

```bash
# Test PostgreSQL connectivity
psql -h localhost -U contact_enrichment -d contact_enrichment

# Check PostgreSQL logs
sudo journalctl -u postgresql -f

# Verify pg_hba.conf
sudo cat /var/lib/pgsql/data/pg_hba.conf | grep contact_enrichment
```

#### Application Startup Failures

```bash
# View application logs
sudo journalctl -u contact-enrichment -f

# Check for missing secrets
ls -la /etc/contact-enrichment/secrets/

# Verify permissions
sudo -u contact-enrichment cat /etc/contact-enrichment/secrets/db_password
```

---

**Next**: [Operations Runbook](../operations/RUNBOOK.md) | [Security Guide](../security/SECURITY.md)
