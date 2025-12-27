# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Repository overview
- Purpose: TOS-compliant contact enrichment backend with strong MAC/SELinux, provenance, and audit guarantees.
- Multi-implementation layout: implementations/java (Spring Boot), implementations/python (FastAPI skeleton), implementations/rust (Actix skeleton), implementations/go (domain scaffolding). Security and architecture docs live under docs/; SELinux policy and installer under scripts/selinux/.

## Commands you’ll use most

### Java (Spring Boot, production-ready)
- Build (no tests):
  - cd implementations/java && ./mvnw clean package -DskipTests
- Run locally (dev profile, HTTP on 8080):
  - cd implementations/java && ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
- Unit tests / Integration tests / Coverage:
  - ./mvnw test
  - ./mvnw verify -Dtest.profile=integration
  - ./mvnw jacoco:report  # report: implementations/java/target/site/jacoco/index.html
- Run a single test or method:
  - ./mvnw -Dtest=ClassName test
  - ./mvnw -Dtest=ClassName#methodName test
- Lint and static analysis (wired in pom.xml):
  - ./mvnw checkstyle:check spotbugs:check pmd:check
- Useful endpoints (dev):
  - REST: http://localhost:8080/api/v1/health
  - Actuator: http://localhost:8080/actuator and /actuator/prometheus

Environment (commonly used): SPRING_PROFILES_ACTIVE, DATABASE_URL/USERNAME/PASSWORD, REDIS_HOST/PORT, JWT_SECRET, SERVER_PORT.

### Python (FastAPI skeleton)
- Install tooling (Poetry):
  - cd implementations/python && poetry install
- Lint/type/security (configured in pyproject.toml):
  - poetry run black . && poetry run ruff . && poetry run mypy .
  - poetry run bandit -r src && poetry run safety check
- Tests with coverage / Single test:
  - poetry run pytest
  - poetry run pytest tests/<path>::TestClass::test_name -q

Notes: current Python tree provides routers and models (e.g., src/contact_enrichment/api/routes.py) but does not wire a FastAPI app entrypoint; add an app factory before running a server (uvicorn).

### Rust (Actix skeleton)
- Build/Run:
  - cd implementations/rust && cargo build
  - HOST=127.0.0.1 PORT=8080 cargo run --bin contact-enrichment
- Tests / Single test / Lints / Audit:
  - cargo test
  - cargo test name_substring
  - cargo fmt -- --check && cargo clippy -- -D warnings
  - cargo audit

Important: main.rs enforces SELinux (calls getenforce) and will exit if not Enforcing. For macOS/local dev, run inside a Linux container/VM or gate the check via a dev feature/flag before local runs.

### Go (scaffolding only)
- Modules present (go 1.21) but no runnable server committed yet. Use go build/go test once cmd/ and packages are added per IMPLEMENTATION_GUIDE.md.

### SELinux policy (TOS integration)
- Install policy (RHEL/SELinux only, requires root):
  - cd scripts/selinux && sudo ./install-policy.sh
- Policy sources: scripts/selinux/contact-enrichment.te

## Big-picture architecture (what matters for changes)
- Domain-Driven Design with shared bounded contexts across implementations: Contact Core, Provenance Ledger, Access Governance, Audit Trail, Enrichment Pipeline, Integration Gateway. See docs/architecture/OVERVIEW.md and DETAILED_ARCHITECTURE.md for diagrams and invariants.
- Layering per implementation: Interfaces (REST/gRPC), Application (use cases), Domain (aggregates, value objects, domain events), Infrastructure (repositories, crypto, cache, bus). Java is the reference implementation; other languages mirror structure.
- Security Kernel as a trusted component surfaces authN/Z, crypto, audit, and session primitives to the application layer; OS-level MAC (SELinux) enforces process and data policies. Shared PostgreSQL schema and RLS assumptions are referenced in docs and Java config.
- Config highlights you’re likely to touch:
  - Java application.yml: profiles (dev/prod), SSL/port, JPA, Redis/Kafka, JWT secrets, rate limits.
  - Rust main.rs: routing under /api/v1, env-driven HOST/PORT/DATABASE_URL, strict SELinux enforcement on startup.
  - Python router prefix: /api/v1/contacts with Pydantic models and security label semantics.

## CI/CD pointers (for reproducing locally)
- The .github/workflows/java-ci.yml pipeline runs: dependency checks (OWASP, Snyk, Trivy), build/test (surefire/failsafe + Postgres/Redis services), coverage (JaCoCo), quality gates (Semgrep), and Docker build. Commands map to the Java section above.

## Gaps and follow-ups noticed while indexing
- README.md links reference files that aren’t in the repo (docs/api/README.md, docs/security/SECURITY.md, docs/operations/RUNBOOK.md, docs/compliance/REGULATORY.md, docs/security/TOS_COMPLIANCE.md, LICENSE). Either add them or update links.
- Java Flyway dependencies are present but no migrations were found; add migration scripts if schema management is expected here.
- Default secrets and credentials in application.yml (e.g., JWT secret, DB password) are fine for dev but must be overridden in non-dev environments.
- Python/Rust/Go implementations are incomplete for running end-to-end; follow IMPLEMENTATION_GUIDE.md to finish wiring app entrypoints, repositories, and migrations.
