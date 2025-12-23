# GitHub Repository Setup Guide

This guide walks you through setting up the Contact Enrichment Platform repository on GitHub with best practices for project management, issues, and branches.

## Table of Contents
- [Create Private Repository](#create-private-repository)
- [Configure Repository Settings](#configure-repository-settings)
- [Set Up Branch Protection](#set-up-branch-protection)
- [Create GitHub Projects](#create-github-projects)
- [Create Initial Issues](#create-initial-issues)
- [Configure Secrets](#configure-secrets)
- [Enable Security Features](#enable-security-features)

## Create Private Repository

### Option 1: GitHub CLI (Recommended)

```bash
# Ensure you're in the repository directory
cd ~/contact-enrichment-tos

# Create private repository
gh repo create yourorg/contact-enrichment-tos \
    --private \
    --source=. \
    --remote=origin \
    --description="TOS-compliant contact enrichment backend with full data provenance and regulatory compliance" \
    --homepage="https://wiki.yourcompany.com/contact-enrichment"

# Push main branch
git push -u origin main

# Create and push implementation branches
git checkout -b impl/java
git push -u origin impl/java

git checkout -b impl/python
git push -u origin impl/python

git checkout -b impl/go
git push -u origin impl/go

git checkout -b impl/rust
git push -u origin impl/rust

# Return to main
git checkout main
```

### Option 2: GitHub Web UI

1. Navigate to https://github.com/new
2. Repository name: `contact-enrichment-tos`
3. Description: `TOS-compliant contact enrichment backend with full data provenance and regulatory compliance`
4. Visibility: **Private**
5. DO NOT initialize with README (we already have one)
6. Click "Create repository"

Then push your local repository:

```bash
cd ~/contact-enrichment-tos
git remote add origin git@github.com:yourorg/contact-enrichment-tos.git
git push -u origin main

# Create implementation branches
git checkout -b impl/java && git push -u origin impl/java
git checkout -b impl/python && git push -u origin impl/python
git checkout -b impl/go && git push -u origin impl/go
git checkout -b impl/rust && git push -u origin impl/rust
git checkout main
```

## Configure Repository Settings

### General Settings

Navigate to: `Settings` → `General`

**Features:**
- ☑ Issues
- ☑ Projects (we'll create them next)
- ☐ Wiki (use Confluence instead)
- ☐ Sponsorships
- ☐ Discussions

**Pull Requests:**
- ☑ Allow squash merging (with custom title)
- ☑ Allow rebase merging
- ☐ Allow merge commits (cleaner history without them)
- ☑ Automatically delete head branches
- ☑ Always suggest updating pull request branches
- ☑ Allow auto-merge

**Merge Button:**
- Default merge message: "Pull request title and description"
- Default commit message: "Pull request title"

**Archival:**
- ☐ Do not archive (this is an active project)

### Collaborators and Teams

Navigate to: `Settings` → `Collaborators and teams`

**Add Teams:**

| Team | Permission | Purpose |
|------|------------|---------|
| `security-team` | Admin | Security reviews, policy updates |
| `platform-engineers` | Write | Implementation, PRs |
| `architects` | Write | Architecture decisions |
| `qa-team` | Triage | Testing, issue management |
| `compliance-team` | Read | Compliance reviews |

**Individual Contributors:**
- Add on case-by-case basis
- Default: Write permission
- Security leads: Admin permission

### Branch Protection Rules

Navigate to: `Settings` → `Branches` → `Add rule`

#### Rule 1: Protect `main`

**Branch name pattern:** `main`

**Protect matching branches:**
- ☑ Require a pull request before merging
  - ☑ Require approvals: **2**
  - ☑ Dismiss stale pull request approvals when new commits are pushed
  - ☑ Require review from Code Owners
  - ☑ Require approval of the most recent reviewable push
- ☑ Require status checks to pass before merging
  - ☑ Require branches to be up to date before merging
  - Required status checks:
    - `Security Scanning / security-scan`
    - `Code Quality / code-quality`
    - `Build & Test / build-and-test`
    - `Compliance Check / compliance-check`
- ☑ Require conversation resolution before merging
- ☑ Require signed commits
- ☑ Require linear history (no merge commits)
- ☑ Include administrators (no one can bypass)
- ☑ Restrict pushes (only via PRs)
- ☑ Allow force pushes: **☐ (disabled)**
- ☑ Allow deletions: **☐ (disabled)**

#### Rule 2: Protect Implementation Branches

**Branch name pattern:** `impl/*`

**Protect matching branches:**
- ☑ Require a pull request before merging
  - ☑ Require approvals: **1**
- ☑ Require status checks to pass before merging
  - Required status checks (language-specific):
    - `Java CI/CD / security-scan`
    - `Java CI/CD / build-and-test`
- ☑ Require conversation resolution before merging
- ☑ Require signed commits
- ☐ Include administrators (allow admin overrides for hotfixes)
- ☑ Restrict pushes (only platform-engineers team)
- ☑ Allow force pushes: **☐ (disabled)**
- ☑ Allow deletions: **☐ (disabled)**

### Code Owners

Create `.github/CODEOWNERS`:

```bash
cat > ~/contact-enrichment-tos/.github/CODEOWNERS << 'EOF'
# Contact Enrichment Platform - Code Owners
# These owners will be automatically requested for review when someone opens a PR

# Default owners for everything
* @yourorg/platform-engineers

# Security-critical components
/scripts/selinux/ @yourorg/security-team
/implementations/*/src/**/security/ @yourorg/security-team
/implementations/*/src/**/crypto/ @yourorg/security-team
*.te @yourorg/security-team
*.pp @yourorg/security-team

# Database schema
/implementations/*/src/main/resources/db/migration/ @yourorg/architects @yourorg/platform-engineers
/implementations/*/migrations/ @yourorg/architects @yourorg/platform-engineers

# Documentation
/docs/ @yourorg/architects
README.md @yourorg/architects
CONTRIBUTING.md @yourorg/architects

# CI/CD pipelines
/.github/workflows/ @yourorg/platform-engineers @yourorg/security-team

# Configuration
*.yml @yourorg/platform-engineers
*.yaml @yourorg/platform-engineers
pom.xml @yourorg/platform-engineers

# Compliance-related
/docs/compliance/ @yourorg/compliance-team @yourorg/security-team
EOF

# Commit CODEOWNERS
cd ~/contact-enrichment-tos
git add .github/CODEOWNERS
git commit -m "chore(github): add code owners for automated review assignments"
git push origin main
```

## Create GitHub Projects

### Project 1: Contact Enrichment Platform - Roadmap

Navigate to: `Projects` → `New project` → `Board`

**Project Name:** Contact Enrichment Platform - Roadmap
**Description:** High-level roadmap for platform development

**Columns:**
1. **Backlog** (Ideas not yet prioritized)
2. **Planned** (Scheduled for upcoming sprints)
3. **In Progress** (Currently being worked on)
4. **Review** (PR created, awaiting review)
5. **Done** (Merged to main)

**Automation:**
- When issue is closed → Move to "Done"
- When PR is created → Move to "Review"
- When PR is merged → Move to "Done"

**Initial Issues to Add:**
- #1: Initialize repository ✅ (Done)
- #2: Complete Java implementation (Planned)
- #3: Complete Python implementation (Planned)
- #4: Complete Go implementation (Planned)
- #5: Complete Rust implementation (Planned)
- #6: Production deployment infrastructure (Backlog)
- #7: Kubernetes operator for auto-scaling (Backlog)

### Project 2: Security & Compliance

Navigate to: `Projects` → `New project` → `Table`

**Project Name:** Security & Compliance Tracker
**Description:** Track security improvements and compliance requirements

**Custom Fields:**
- **Severity:** P0 (Critical), P1 (High), P2 (Medium), P3 (Low)
- **Compliance Framework:** GDPR, CCPA, SOC2, HIPAA, ISO27001
- **Security Domain:** Authentication, Authorization, Encryption, Audit, Network
- **Remediation Status:** Not Started, In Progress, Testing, Deployed

**Views:**
1. **By Severity** (Group by Severity)
2. **By Framework** (Group by Compliance Framework)
3. **Security Backlog** (Filter: Status = Not Started, Sort by Severity)

## Create Initial Issues

### Issue Labels

First, create standardized labels:

Navigate to: `Issues` → `Labels` → `New label`

| Label | Color | Description |
|-------|-------|-------------|
| `bug` | `#d73a4a` | Something isn't working |
| `enhancement` | `#a2eeef` | New feature or request |
| `security` | `#b60205` | Security improvement |
| `documentation` | `#0075ca` | Documentation updates |
| `P0-critical` | `#b60205` | Critical priority |
| `P1-high` | `#ff6600` | High priority |
| `P2-medium` | `#fbca04` | Medium priority |
| `P3-low` | `#0e8a16` | Low priority |
| `java` | `#5319e7` | Java implementation |
| `python` | `#3572A5` | Python implementation |
| `go` | `#00ADD8` | Go implementation |
| `rust` | `#dea584` | Rust implementation |
| `selinux` | `#1d76db` | SELinux policy |
| `compliance` | `#c5def5` | Regulatory compliance |
| `infrastructure` | `#d4c5f9` | Infrastructure as code |

### Create Issues Using GitHub CLI

```bash
# Issue #1: Initialize repository (already done)
gh issue create \
    --title "feat(init): initialize repository with base architecture" \
    --body "$(cat << 'ISSUE1'
## Summary
Set up initial repository structure with:
- Domain-Driven Design architecture
- SELinux security policy
- CI/CD pipelines
- Comprehensive documentation

## Acceptance Criteria
- [x] Repository created with proper structure
- [x] SELinux policy defined
- [x] CI/CD workflows configured
- [x] Documentation (README, CONTRIBUTING, architecture)
- [x] Initial commit follows conventional commits

## Labels
- `enhancement`
- `P0-critical`
- `documentation`
ISSUE1
)" \
    --label "enhancement,P0-critical,documentation" \
    --assignee "@me"

# Close it immediately (already done)
gh issue close 1 --comment "Completed in initial commit (5837e57)"

# Issue #2: Complete Java implementation
gh issue create \
    --title "feat(java): complete Spring Boot implementation with full DDD" \
    --body "$(cat << 'ISSUE2'
## Summary
Complete the Java Spring Boot implementation with all 6 bounded contexts.

## Tasks
- [x] Domain model (Contact, Provenance, SecurityLabel, EncryptedValue)
- [ ] Repository implementations with Row-Level Security
- [ ] Application services (use cases)
- [ ] REST API controllers with OpenAPI
- [ ] Security kernel integration
- [ ] Cryptographic services (HSM integration)
- [ ] Database migrations (Flyway)
- [ ] Unit tests (80%+ coverage)
- [ ] Integration tests (Testcontainers)
- [ ] Architecture tests (ArchUnit)
- [ ] Performance tests (JMeter)

## Acceptance Criteria
- All domain aggregates implemented
- Full CRUD operations for contacts
- Enrichment pipeline functional
- Provenance tracking working
- Audit trail immutable and signed
- SELinux integration tested
- All tests passing
- Security scans clean

## Dependencies
- None (foundational)

## Estimated Effort
- 3-4 weeks (1 sprint)

## Labels
- `enhancement`
- `P0-critical`
- `java`
ISSUE2
)" \
    --label "enhancement,P0-critical,java" \
    --milestone "MVP Release" \
    --assignee "@me"

# Issue #3: Complete Python implementation
gh issue create \
    --title "feat(python): complete FastAPI implementation with async support" \
    --body "Complete Python implementation with FastAPI, async/await, and Pydantic validation." \
    --label "enhancement,P1-high,python" \
    --milestone "MVP Release"

# Issue #4: Complete Go implementation
gh issue create \
    --title "feat(go): complete Go implementation with native performance" \
    --body "Complete Go implementation optimized for high throughput and low latency." \
    --label "enhancement,P1-high,go" \
    --milestone "Post-MVP"

# Issue #5: Complete Rust implementation
gh issue create \
    --title "feat(rust): complete Rust implementation for maximum security guarantees" \
    --body "Complete Rust implementation with memory safety and zero-cost abstractions." \
    --label "enhancement,P2-medium,rust" \
    --milestone "Post-MVP"

# Issue #6: SELinux policy refinement
gh issue create \
    --title "security(selinux): refine SELinux policy based on runtime testing" \
    --body "Test SELinux policy in production-like environment and refine based on audit2why analysis." \
    --label "security,P1-high,selinux" \
    --milestone "MVP Release"

# Issue #7: Production deployment infrastructure
gh issue create \
    --title "feat(infra): create Terraform/Ansible for production deployment" \
    --body "Infrastructure as code for deploying to production RHEL 9 environment." \
    --label "enhancement,infrastructure,P1-high" \
    --milestone "Production Readiness"

# Issue #8: Kubernetes operator
gh issue create \
    --title "feat(k8s): create Kubernetes operator for auto-scaling" \
    --body "Custom K8s operator to manage contact enrichment platform lifecycle and auto-scaling." \
    --label "enhancement,infrastructure,P3-low" \
    --milestone "Future"

# Issue #9: GDPR compliance verification
gh issue create \
    --title "docs(compliance): document GDPR compliance controls" \
    --body "Comprehensive documentation of how platform satisfies GDPR Articles 5-22." \
    --label "documentation,compliance,P1-high" \
    --milestone "Production Readiness"

# Issue #10: Penetration testing
gh issue create \
    --title "security(pentest): conduct penetration testing" \
    --body "Third-party penetration testing before production deployment." \
    --label "security,P0-critical" \
    --milestone "Production Readiness"
```

### Create Milestones

```bash
# MVP Release (Q1 2025)
gh api repos/:owner/:repo/milestones \
    -f title="MVP Release" \
    -f description="Minimum viable product with Java implementation and core features" \
    -f due_on="2025-03-31T23:59:59Z"

# Production Readiness (Q2 2025)
gh api repos/:owner/:repo/milestones \
    -f title="Production Readiness" \
    -f description="Production-ready with all compliance and security controls" \
    -f due_on="2025-06-30T23:59:59Z"

# Post-MVP (Q3 2025)
gh api repos/:owner/:repo/milestones \
    -f title="Post-MVP" \
    -f description="Additional language implementations and performance optimizations" \
    -f due_on="2025-09-30T23:59:59Z"

# Future
gh api repos/:owner/:repo/milestones \
    -f title="Future" \
    -f description="Long-term enhancements and nice-to-have features"
```

## Configure Secrets

Navigate to: `Settings` → `Secrets and variables` → `Actions` → `New repository secret`

**Required Secrets:**

| Secret Name | Description | How to Generate |
|-------------|-------------|-----------------|
| `SONAR_TOKEN` | SonarQube authentication | SonarQube → My Account → Security → Generate Token |
| `SONAR_HOST_URL` | SonarQube server URL | e.g., `https://sonarqube.yourcompany.com` |
| `SNYK_TOKEN` | Snyk vulnerability scanning | Snyk → Account Settings → API Token |
| `CODECOV_TOKEN` | Code coverage reporting | Codecov → Repository Settings → Token |
| `GPG_PRIVATE_KEY` | Commit signing (optional) | `gpg --export-secret-keys --armor KEY_ID` |
| `GPG_PASSPHRASE` | GPG key passphrase | Your GPG passphrase |

**Optional Secrets (for deployment):**

| Secret Name | Description |
|-------------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS credentials for deployment |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `DOCKER_USERNAME` | Docker Hub username |
| `DOCKER_PASSWORD` | Docker Hub password/token |

## Enable Security Features

Navigate to: `Settings` → `Code security and analysis`

**Enable All Features:**
- ☑ Dependency graph
- ☑ Dependabot alerts
- ☑ Dependabot security updates
- ☑ Grouped security updates
- ☑ Dependabot version updates (create `dependabot.yml`)
- ☑ Code scanning (CodeQL)
- ☑ Secret scanning
- ☑ Push protection (prevent secrets in commits)

### Configure Dependabot

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  # Java dependencies (Maven)
  - package-ecosystem: "maven"
    directory: "/implementations/java"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "yourorg/platform-engineers"
    labels:
      - "dependencies"
      - "java"
    commit-message:
      prefix: "build(deps)"

  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/implementations/python"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "python"

  # Go dependencies
  - package-ecosystem: "gomod"
    directory: "/implementations/go"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "go"

  # Rust dependencies
  - package-ecosystem: "cargo"
    directory: "/implementations/rust"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "rust"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "ci"
```

## Final Verification

```bash
# Verify repository structure
tree -L 2 ~/contact-enrichment-tos

# Verify branches
git branch -a

# Verify remote
git remote -v

# Verify commit signature (if GPG configured)
git log --show-signature -1

# Verify CI/CD workflows
gh workflow list

# Verify issues
gh issue list

# Verify projects
gh project list

# Verify security features
gh api repos/:owner/:repo | jq '{
    has_issues: .has_issues,
    has_projects: .has_projects,
    security_and_analysis: .security_and_analysis
}'
```

## Next Steps

1. **Invite Team Members**: Add collaborators and teams
2. **Configure Branch Protection**: Ensure all rules are active
3. **Set Up Notifications**: Configure Slack/email for critical events
4. **Create First PR**: Test the full workflow end-to-end
5. **Security Audit**: Run initial security scans
6. **Documentation Review**: Ensure all docs are accurate

---

**Repository is now fully configured and ready for development!**
