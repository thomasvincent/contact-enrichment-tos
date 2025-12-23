# Implementation Guide for Remaining Languages

This guide provides a roadmap for implementing the Python, Go, and Rust versions of the Contact Enrichment Platform.

## Overview

The Java implementation serves as the reference architecture. All other implementations should follow the same:
- Domain-Driven Design principles
- Security patterns (encryption, MAC, audit)
- Database schema
- API contracts (OpenAPI specification)
- SELinux policy integration

## Implementation Status

| Language | Status | Branch | Priority | Target Date |
|----------|--------|--------|----------|-------------|
| **Java** | ✅ Core Complete | `impl/java` | P0 | Q1 2025 |
| **Python** | 🟡 Pending | `impl/python` | P1 | Q1 2025 |
| **Go** | ⚪ Pending | `impl/go` | P1 | Q2 2025 |
| **Rust** | ⚪ Pending | `impl/rust` | P2 | Q3 2025 |

## Python Implementation (FastAPI)

### Tech Stack
- **Framework**: FastAPI 0.108+ with async/await
- **ORM**: SQLAlchemy 2.0+ with async support
- **Validation**: Pydantic V2
- **Database**: asyncpg for PostgreSQL
- **Cache**: aioredis for Redis
- **Security**: python-jose (JWT), cryptography (encryption)
- **Testing**: pytest + pytest-asyncio

### Directory Structure

```
implementations/python/
├── pyproject.toml              # Poetry/pip dependencies
├── requirements.txt            # Locked dependencies
├── requirements-dev.txt        # Development dependencies
├── Dockerfile                  # Multi-stage build
├── .python-version            # Python 3.11
├── src/
│   └── contact_enrichment/
│       ├── __init__.py
│       ├── main.py            # FastAPI application
│       ├── domain/            # Domain layer (DDD)
│       │   ├── model/
│       │   │   ├── contact.py
│       │   │   ├── provenance.py
│       │   │   ├── security_label.py
│       │   │   └── encrypted_value.py
│       │   ├── repository/    # Repository interfaces
│       │   └── service/       # Domain services
│       ├── application/       # Use cases
│       │   ├── contact_service.py
│       │   ├── enrichment_service.py
│       │   └── provenance_service.py
│       ├── infrastructure/    # Infrastructure
│       │   ├── database/
│       │   │   ├── models.py  # SQLAlchemy models
│       │   │   └── repositories.py
│       │   ├── security/
│       │   │   ├── crypto.py
│       │   │   ├── kernel.py
│       │   │   └── selinux.py
│       │   └── external/      # Vendor integrations
│       ├── interfaces/        # API layer
│       │   ├── api/
│       │   │   ├── v1/
│       │   │   │   ├── contacts.py
│       │   │   │   ├── enrichment.py
│       │   │   │   └── provenance.py
│       │   │   └── dependencies.py
│       │   └── schemas/       # Pydantic models
│       └── config/
│           └── settings.py    # Pydantic settings
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
└── alembic/                   # Database migrations
    └── versions/
```

### Key Implementation Points

#### 1. Domain Model (Immutability)

```python
from dataclasses import dataclass
from typing import FrozenSet
from enum import Enum

@dataclass(frozen=True)  # Immutable!
class SecurityLabel:
    """Immutable security label value object."""
    confidentiality: ConfidentialityLevel
    integrity: IntegrityLevel
    compartments: FrozenSet[str]  # Use FrozenSet, not Set

    def dominates(self, other: "SecurityLabel") -> bool:
        return (
            self.confidentiality.value >= other.confidentiality.value
            and self.integrity.value >= other.integrity.value
            and self.compartments.issuperset(other.compartments)
        )

class ConfidentialityLevel(Enum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3
```

#### 2. Async Repository Pattern

```python
from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

class ContactRepository(ABC):
    """Async repository for Contact aggregate."""

    @abstractmethod
    async def find_by_id(
        self,
        contact_id: UUID,
        context: SecurityContext
    ) -> Optional[Contact]:
        """Find contact with MAC enforcement."""
        pass

    @abstractmethod
    async def save(
        self,
        contact: Contact,
        context: SecurityContext
    ) -> None:
        """Save contact with audit trail."""
        pass
```

#### 3. FastAPI Dependency Injection

```python
from fastapi import Depends, HTTPException
from typing import Annotated

async def get_security_context(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> SecurityContext:
    """Extract security context from JWT."""
    context = await security_kernel.verify_session(token)
    if context is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return context

@app.post("/api/v1/contacts", status_code=201)
async def create_contact(
    request: ContactCreateRequest,
    context: Annotated[SecurityContext, Depends(get_security_context)],
    service: Annotated[ContactService, Depends(get_contact_service)]
) -> ContactResponse:
    """Create new contact with security enforcement."""
    contact = await service.create_contact(request, context)
    return ContactResponse.from_domain(contact)
```

### Testing Strategy

```bash
# Unit tests with mocking
pytest tests/unit/ -v --cov=src --cov-report=html

# Integration tests with Testcontainers
pytest tests/integration/ -v --tb=short

# E2E tests against real database
pytest tests/e2e/ -v --slow

# Security tests
bandit -r src/
safety check
semgrep --config=p/security-audit src/
```

### Security Checklist
- [ ] All PII encrypted using `cryptography.hazmat`
- [ ] Input validation with Pydantic validators
- [ ] Output encoding with `html.escape()` where needed
- [ ] No SQL injection (use SQLAlchemy ORM)
- [ ] No secrets in code (use environment variables)
- [ ] Audit logging for all operations
- [ ] Rate limiting with `slowapi`

---

## Go Implementation

### Tech Stack
- **Framework**: Gin 1.9+ or Echo 4.11+
- **ORM**: sqlx (raw SQL) or GORM 1.25+
- **Validation**: go-playground/validator/v10
- **Database**: pgx/v5 for PostgreSQL
- **Cache**: go-redis/v9
- **Security**: golang.org/x/crypto
- **Testing**: testify + testcontainers-go

### Directory Structure

```
implementations/go/
├── go.mod
├── go.sum
├── Dockerfile
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── domain/              # Domain layer
│   │   ├── model/
│   │   │   ├── contact.go
│   │   │   ├── provenance.go
│   │   │   └── security_label.go
│   │   ├── repository/
│   │   └── service/
│   ├── application/         # Use cases
│   │   ├── contact_service.go
│   │   └── enrichment_service.go
│   ├── infrastructure/
│   │   ├── database/
│   │   ├── security/
│   │   └── crypto/
│   └── interfaces/
│       ├── api/
│       │   ├── handler/
│       │   └── middleware/
│       └── dto/
├── pkg/                     # Shared packages
│   └── selinux/
├── migrations/              # goose or migrate
├── tests/
│   ├── unit/
│   └── integration/
└── scripts/
```

### Key Implementation Points

#### 1. Value Objects (Immutability)

```go
package model

// SecurityLabel is an immutable value object for MAC
type SecurityLabel struct {
    confidentiality ConfidentialityLevel
    integrity       IntegrityLevel
    compartments    map[string]struct{} // Read-only after construction
}

// NewSecurityLabel creates an immutable security label
func NewSecurityLabel(
    conf ConfidentialityLevel,
    integ IntegrityLevel,
    compartments []string,
) SecurityLabel {
    // Defensive copy
    comps := make(map[string]struct{}, len(compartments))
    for _, c := range compartments {
        comps[c] = struct{}{}
    }

    return SecurityLabel{
        confidentiality: conf,
        integrity:       integ,
        compartments:    comps, // No external reference
    }
}

// Dominates checks if this label can access data with other label
func (sl SecurityLabel) Dominates(other SecurityLabel) bool {
    if sl.confidentiality < other.confidentiality {
        return false
    }
    if sl.integrity < other.integrity {
        return false
    }

    // Check compartments (must be superset)
    for comp := range other.compartments {
        if _, has := sl.compartments[comp]; !has {
            return false
        }
    }

    return true
}
```

#### 2. Repository with Context

```go
package repository

import (
    "context"
    "github.com/google/uuid"
)

type ContactRepository interface {
    FindByID(ctx context.Context, id uuid.UUID, secCtx SecurityContext) (*Contact, error)
    Save(ctx context.Context, contact *Contact, secCtx SecurityContext) error
}

type PostgresContactRepository struct {
    db *sqlx.DB
}

func (r *PostgresContactRepository) FindByID(
    ctx context.Context,
    id uuid.UUID,
    secCtx SecurityContext,
) (*Contact, error) {
    // Set security context in database session
    _, err := r.db.ExecContext(ctx, `
        SET LOCAL app.user_clearance_confidentiality = $1;
        SET LOCAL app.user_clearance_integrity = $2;
    `, secCtx.Clearance.Confidentiality, secCtx.Clearance.Integrity)
    if err != nil {
        return nil, err
    }

    // Query with Row-Level Security automatically enforced
    var contact Contact
    err = r.db.GetContext(ctx, &contact, `
        SELECT * FROM contacts WHERE id = $1
    `, id)

    return &contact, err
}
```

### Security Checklist
- [ ] Use `crypto/rand` for random generation
- [ ] Constant-time comparisons with `subtle.ConstantTimeCompare`
- [ ] No SQL injection (use `$1`, `$2` placeholders)
- [ ] Context cancellation for timeout protection
- [ ] TLS 1.3 with `crypto/tls` MinVersion
- [ ] Input validation with `validator` package
- [ ] Error wrapping with `fmt.Errorf("%w", err)`

---

## Rust Implementation

### Tech Stack
- **Framework**: Actix-web 4.4+ or Axum 0.7+
- **ORM**: SeaORM 0.12+ or sqlx 0.7+
- **Validation**: validator 0.16+
- **Database**: tokio-postgres 0.7+
- **Cache**: redis-rs 0.24+ (async)
- **Security**: ring 0.17+ (crypto), jsonwebtoken 9.2+
- **Testing**: cargo test + testcontainers-rs

### Directory Structure

```
implementations/rust/
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── src/
│   ├── main.rs
│   ├── domain/
│   │   ├── mod.rs
│   │   ├── model/
│   │   │   ├── contact.rs
│   │   │   ├── provenance.rs
│   │   │   └── security_label.rs
│   │   ├── repository.rs
│   │   └── service/
│   ├── application/
│   │   ├── contact_service.rs
│   │   └── enrichment_service.rs
│   ├── infrastructure/
│   │   ├── database/
│   │   ├── security/
│   │   └── crypto/
│   └── interfaces/
│       ├── api/
│       │   ├── handlers/
│       │   └── middleware/
│       └── dto/
├── tests/
│   ├── unit/
│   └── integration/
└── migrations/
```

### Key Implementation Points

#### 1. Type Safety and Ownership

```rust
use std::sync::Arc;
use uuid::Uuid;

/// Immutable security label (Copy + Clone for efficiency)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLabel {
    confidentiality: ConfidentialityLevel,
    integrity: IntegrityLevel,
    // Compartments stored separately to avoid unbounded Copy
}

impl SecurityLabel {
    pub fn new(
        confidentiality: ConfidentialityLevel,
        integrity: IntegrityLevel,
    ) -> Self {
        Self {
            confidentiality,
            integrity,
        }
    }

    pub fn dominates(&self, other: &SecurityLabel) -> bool {
        self.confidentiality >= other.confidentiality
            && self.integrity >= other.integrity
    }
}

/// Contact aggregate with ownership guarantees
pub struct Contact {
    id: Uuid,
    security_label: SecurityLabel,
    // Vec owns the data, preventing external mutation
    enriched_attributes: Vec<EnrichedAttribute>,
}

impl Contact {
    /// Add enrichment with move semantics (takes ownership)
    pub fn add_enrichment(&mut self, attr: EnrichedAttribute) -> Result<(), Error> {
        // Validate security label dominance
        if !self.security_label.dominates(&attr.security_label) {
            return Err(Error::SecurityViolation);
        }

        // Move attribute into contact (ownership transferred)
        self.enriched_attributes.push(attr);
        Ok(())
    }
}
```

#### 2. Async Repository with Error Handling

```rust
use async_trait::async_trait;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

#[async_trait]
pub trait ContactRepository: Send + Sync {
    async fn find_by_id(
        &self,
        id: Uuid,
        context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError>;

    async fn save(
        &self,
        contact: &Contact,
        context: &SecurityContext,
    ) -> Result<(), RepositoryError>;
}

pub struct PostgresContactRepository {
    pool: PgPool,
}

#[async_trait]
impl ContactRepository for PostgresContactRepository {
    async fn find_by_id(
        &self,
        id: Uuid,
        context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError> {
        // Set security context
        sqlx::query("SET LOCAL app.user_clearance_confidentiality = $1")
            .bind(&context.clearance.confidentiality.to_string())
            .execute(&self.pool)
            .await?;

        // Query with RLS enforcement
        let contact = sqlx::query_as::<_, ContactRow>(
            "SELECT * FROM contacts WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(Into::into);

        Ok(contact)
    }
}
```

### Security Checklist
- [ ] Use `ring` or `rustls` for TLS
- [ ] Use `subtle` crate for constant-time comparisons
- [ ] No `unwrap()` in production code (use `?` or `match`)
- [ ] Use `secrecy` crate for sensitive strings
- [ ] Enable Clippy lints: `clippy::unwrap_used`, `clippy::expect_used`
- [ ] Use `cargo audit` for dependency vulnerabilities
- [ ] Use `cargo deny` for license compliance

---

## Shared Components

### Database Schema
All implementations use the **same PostgreSQL schema** defined in `docs/setup/INSTALLATION.md`.

### OpenAPI Specification
All implementations must conform to the same API contract. Generate client SDKs from the OpenAPI spec.

### SELinux Policy
All implementations use the **same SELinux policy** with different process domains if needed.

---

## Testing Matrix

| Test Type | Java | Python | Go | Rust |
|-----------|------|--------|----|----- |
| Unit | JUnit 5 | pytest | testify | cargo test |
| Integration | Testcontainers | Testcontainers | testcontainers-go | testcontainers-rs |
| E2E | RestAssured | httpx | net/http | reqwest |
| Coverage | JaCoCo | coverage.py | go test -cover | tarpaulin |
| Target | 80%+ | 80%+ | 80%+ | 80%+ |

---

## Next Steps

1. **Set up Python branch**: `git checkout -b impl/python`
2. **Copy domain model from Java**: Translate to Python patterns
3. **Set up FastAPI project**: Use `poetry` or `pip-tools`
4. **Implement repositories**: Async with SQLAlchemy
5. **Write tests**: Start with domain model tests
6. **Iterate**: Feature by feature, following Java reference

Good luck! Refer to the Java implementation for domain logic, and adapt to each language's idioms.
