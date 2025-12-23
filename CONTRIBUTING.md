# Contributing Guide

Thank you for contributing to the Contact Enrichment Platform! This document provides guidelines for contributing to this private repository.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Code Standards](#code-standards)
- [Security Requirements](#security-requirements)

## Code of Conduct

- Be professional and respectful
- Follow secure coding practices
- Document all security-relevant changes
- Report security vulnerabilities privately to security@yourcompany.com

## Getting Started

### Prerequisites
- Approved access to this private repository
- Development environment matching target production (RHEL 9+, SELinux enforcing)
- Required tools installed (see docs/setup/INSTALLATION.md)

### Clone Repository

```bash
git clone git@github.com:yourorg/contact-enrichment-tos.git
cd contact-enrichment-tos
```

### Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code, protected |
| `impl/java` | Java implementation (Spring Boot) |
| `impl/python` | Python implementation (FastAPI) |
| `impl/go` | Go implementation |
| `impl/rust` | Rust implementation |
| `feature/*` | New features |
| `fix/*` | Bug fixes |
| `security/*` | Security improvements |

## Development Workflow

### 1. Create an Issue

**Before writing code**, create a GitHub issue:

```markdown
Title: [FEATURE]: Add data retention policy enforcement

**Description:**
Implement automated data retention policy that deletes contact records
older than 7 years in compliance with GDPR Article 5(1)(e).

**Acceptance Criteria:**
- [ ] Policy configuration interface
- [ ] Automated deletion job
- [ ] Audit trail for deletions
- [ ] Documentation updated
```

### 2. Create a Branch

Branch names must reference the issue number:

```bash
# Feature branches
git checkout -b feature/123-data-retention-policy

# Bug fix branches
git checkout -b fix/456-selinux-denial-on-startup

# Security improvements
git checkout -b security/789-upgrade-encryption-algorithm
```

### 3. Implement Changes

Follow the coding standards for your implementation language (see below).

### 4. Test Thoroughly

```bash
# Unit tests
./mvnw test  # Java
pytest      # Python
go test ./... # Go
cargo test   # Rust

# Integration tests
./mvnw verify -P integration-tests

# Security tests
./mvnw verify -P security-tests
```

### 5. Commit Changes

See [Commit Message Format](#commit-message-format) below.

### 6. Push and Create Pull Request

```bash
git push origin feature/123-data-retention-policy
```

Then create a pull request via GitHub UI.

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type

Must be one of:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `build`: Build system or dependencies
- `ci`: CI/CD configuration
- `chore`: Other changes (no production code)
- `security`: Security improvement or vulnerability fix

### Scope

Scope should indicate the affected component:

- `contact-core`: Contact domain
- `provenance`: Provenance ledger
- `audit`: Audit trail
- `crypto`: Cryptography
- `selinux`: SELinux policy
- `api`: REST API
- `db`: Database schema
- `docs`: Documentation

### Subject

- Use imperative mood ("add" not "added" or "adds")
- Don't capitalize first letter
- No period at the end
- Limit to 50 characters

### Body

- Wrap at 72 characters
- Explain *what* and *why*, not *how*
- Reference issues and pull requests

### Footer

- Reference issues: `Fixes #123` or `Closes #456`
- Breaking changes: `BREAKING CHANGE: <description>`
- Co-authors: `Co-authored-by: Name <email>`

### Examples

#### Good Examples

```
feat(contact-core): add temporal validity for enriched attributes

Implement temporal validity pattern to track attribute value changes
over time. Supports querying attribute history and point-in-time views.

- Add valid_from and valid_until timestamps
- Prevent overlapping validity periods with exclusion constraint
- Add query methods for current and historical attributes

Closes #123
```

```
security(crypto): upgrade encryption to AES-256-GCM from AES-128-CBC

AES-128-CBC is vulnerable to padding oracle attacks. Migrate to
authenticated encryption (AEAD) using AES-256-GCM.

BREAKING CHANGE: Existing encrypted data must be re-encrypted.
Run migration: ./scripts/crypto-migration.sh

Fixes #456
```

```
fix(selinux): allow database connections from enrichment domain

SELinux policy was too restrictive, preventing enrichment workers
from connecting to PostgreSQL. Add necessary allow rules.

- Allow contact_enrichment_db_t to connect to postgresql_port_t
- Test policy with audit2allow

Fixes #789
```

#### Bad Examples

```
❌ Updated code
   (Too vague, no type, no context)

❌ feat: Added new feature for handling contacts better
   (Missing scope, subject too long, not imperative)

❌ FIXED BUG
   (All caps, no useful information)

❌ refactor(contact-core): Refactored the contact service because the old code was messy
   (Not imperative, explanation should be in body)
```

## Pull Request Process

### PR Title

Use same format as commit messages:

```
feat(contact-core): add temporal validity for enriched attributes
```

### PR Description Template

```markdown
## Summary
Brief description of what this PR does.

## Related Issues
Fixes #123
Relates to #456

## Changes Made
- [ ] Implemented feature X
- [ ] Added tests for Y
- [ ] Updated documentation

## Testing
Describe how you tested these changes:
- Unit tests: `./mvnw test`
- Integration tests: `./mvnw verify`
- Manual testing: Verified on RHEL 9 with SELinux enforcing

## Security Considerations
- [ ] No new secrets in code
- [ ] Input validation added
- [ ] Output encoding applied
- [ ] Audit logging included
- [ ] Security tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] No new compiler warnings
- [ ] Security scan passes (Snyk, SpotBugs)
- [ ] Commit messages follow Conventional Commits
- [ ] PR title follows Conventional Commits

## Screenshots (if applicable)
```

### Review Process

1. **Automated Checks**: CI/CD pipeline must pass
   - Build successful
   - All tests pass (unit + integration)
   - Security scans clean (SAST, dependency check)
   - Code coverage >= 80%
   - No SELinux policy violations

2. **Peer Review**: At least 2 approvals required from:
   - One domain expert (for logic/architecture)
   - One security reviewer (for security implications)

3. **Security Review**: Required for changes to:
   - Cryptography
   - Authentication/authorization
   - SELinux policy
   - Data handling
   - External integrations

### Merge Strategy

- **Squash and merge** for feature branches (creates clean history)
- **Rebase and merge** for hotfixes (preserves individual commits)
- **No force push** to protected branches

## Code Standards

### Java (Spring Boot)

**Style**: [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html)

**Security Rules**:
```java
// ✅ GOOD: Input validation
public Contact createContact(@Valid ContactCreateRequest request) {
    String email = validator.sanitizeEmail(request.getEmail());
    // ...
}

// ❌ BAD: No validation
public Contact createContact(ContactCreateRequest request) {
    repository.save(request.getEmail()); // Injection risk!
}

// ✅ GOOD: Output encoding
log.info("Contact created: {}", Encode.forJava(contact.getId()));

// ❌ BAD: Log injection
log.info("Contact created: " + contact.getId()); // Injection risk!

// ✅ GOOD: Immutable value objects
@Value // Lombok generates immutable class
public class SecurityLabel {
    ConfidentialityLevel confidentiality;
    IntegrityLevel integrity;
}

// ❌ BAD: Mutable security-critical objects
public class SecurityLabel {
    public ConfidentialityLevel confidentiality; // Can be changed!
}
```

**Checkstyle**: Enforced in CI, run locally:
```bash
./mvnw checkstyle:check
```

### Python (FastAPI)

**Style**: [PEP 8](https://pep8.org/) + [Black](https://black.readthedocs.io/)

**Security Rules**:
```python
# ✅ GOOD: Type hints + validation
from pydantic import BaseModel, EmailStr, validator

class ContactCreate(BaseModel):
    email: EmailStr  # Validated email format
    full_name: str

    @validator('full_name')
    def sanitize_name(cls, v):
        return html.escape(v)  # Prevent XSS

# ❌ BAD: No validation
def create_contact(email: str, name: str):
    db.execute(f"INSERT INTO contacts VALUES ('{email}', '{name}')")  # SQL injection!

# ✅ GOOD: Immutable dataclasses
from dataclasses import dataclass
from typing import FrozenSet

@dataclass(frozen=True)
class SecurityLabel:
    confidentiality: ConfidentialityLevel
    compartments: FrozenSet[str]

# ❌ BAD: Mutable security objects
class SecurityLabel:
    def __init__(self):
        self.compartments = []  # Can be modified externally!
```

**Linting**: Run before commit:
```bash
black .
flake8 .
mypy .
bandit -r .  # Security linter
```

### Go

**Style**: [Effective Go](https://golang.org/doc/effective_go) + `gofmt`

**Security Rules**:
```go
// ✅ GOOD: Prepared statements
stmt, err := db.Prepare("INSERT INTO contacts (email) VALUES ($1)")
defer stmt.Close()
stmt.Exec(sanitizedEmail)

// ❌ BAD: String concatenation (SQL injection)
db.Exec("INSERT INTO contacts VALUES ('" + email + "')")

// ✅ GOOD: Constant-time comparison
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 {
    // Authenticated
}

// ❌ BAD: Timing attacks
if provided == expected {  // Vulnerable to timing attacks
    // Authenticated
}
```

### Rust

**Style**: `rustfmt` + `clippy`

**Security Rules**:
```rust
// ✅ GOOD: Ownership prevents use-after-free
fn process_contact(contact: Contact) -> Result<(), Error> {
    let encrypted = encrypt(contact.email)?;
    // contact dropped here, can't be used
    Ok(())
}

// ✅ GOOD: Explicit error handling
match decrypt(&ciphertext) {
    Ok(plaintext) => process(plaintext),
    Err(e) => {
        audit_log("Decryption failed", &e);
        return Err(e);
    }
}

// ❌ BAD: Unwrapping (panics)
let plaintext = decrypt(&ciphertext).unwrap();  // Crashes on error!
```

## Security Requirements

### Critical Security Rules

1. **No Secrets in Code**: Use environment variables or secrets manager
   ```bash
   # ✅ GOOD
   DB_PASSWORD=$(cat /etc/contact-enrichment/secrets/db_password)

   # ❌ BAD
   DB_PASSWORD="hardcoded_password_123"
   ```

2. **Input Validation**: Validate all external input
   - Email addresses
   - Phone numbers
   - Names (prevent XSS)
   - File uploads (size, type, content)

3. **Output Encoding**: Encode data before output
   - HTML context: Use OWASP Encoder
   - SQL context: Use parameterized queries
   - Logs: Escape newlines, special chars

4. **Encryption**: Always encrypt PII
   - Use AES-256-GCM (authenticated encryption)
   - Never implement custom crypto
   - Rotate keys regularly

5. **Audit Logging**: Log security events
   - Authentication attempts
   - Authorization failures
   - Data access
   - Configuration changes

6. **Error Handling**: Don't leak information
   ```java
   // ✅ GOOD: Generic error message
   throw new AuthenticationException("Invalid credentials");

   // ❌ BAD: Leaks information
   throw new AuthenticationException("User 'admin' not found");
   ```

### Security Testing

Run security tests before every PR:

```bash
# Dependency vulnerabilities
./mvnw org.owasp:dependency-check-maven:check

# Static analysis
./mvnw spotbugs:check

# Secret detection
trufflehog filesystem . --only-verified

# Container scanning (if using Docker)
trivy image contact-enrichment:latest
```

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Email: security@yourcompany.com

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 24 hours.

---

**Questions?** Contact the development team on Slack: #contact-enrichment-platform
