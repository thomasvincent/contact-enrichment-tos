#!/bin/bash
############################################################################
# SELinux Policy Installation Script
# Contact Enrichment Platform - Trusted Operating System Edition
#
# This script compiles and installs the custom SELinux policy for the
# contact enrichment platform, following best practices for trusted
# operating environments.
#
# Prerequisites:
# - RHEL 9+ with SELinux in enforcing mode
# - policycoreutils-python-utils package installed
# - selinux-policy-devel package installed
#
# Usage:
#   sudo ./install-policy.sh
#
# Author: Security Team
# Version: 1.0.0
############################################################################

set -euo pipefail
IFS=$'\n\t'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check SELinux status
if ! command -v sestatus &> /dev/null; then
    log_error "SELinux tools not found. Please install policycoreutils."
    exit 1
fi

SELINUX_STATUS=$(sestatus | grep "SELinux status" | awk '{print $3}')
if [[ "$SELINUX_STATUS" != "enabled" ]]; then
    log_error "SELinux is not enabled. This platform requires SELinux enforcing mode."
    exit 1
fi

SELINUX_MODE=$(sestatus | grep "Current mode" | awk '{print $3}')
if [[ "$SELINUX_MODE" != "enforcing" ]]; then
    log_warn "SELinux is not in enforcing mode (current: $SELINUX_MODE)"
    log_warn "For production deployments, SELinux must be in enforcing mode"
fi

log_info "SELinux Status: $SELINUX_STATUS (Mode: $SELINUX_MODE)"

# Navigate to policy directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log_info "Compiling SELinux policy module..."

# Check if policy file exists
if [[ ! -f "contact-enrichment.te" ]]; then
    log_error "Policy file contact-enrichment.te not found in $SCRIPT_DIR"
    exit 1
fi

# Compile policy module
if ! checkmodule -M -m -o contact_enrichment.mod contact-enrichment.te; then
    log_error "Failed to compile SELinux policy"
    exit 1
fi

log_info "Policy compiled successfully"

# Create policy package
log_info "Creating policy package..."
if ! semodule_package -o contact_enrichment.pp -m contact_enrichment.mod; then
    log_error "Failed to create policy package"
    exit 1
fi

log_info "Policy package created successfully"

# Install policy module
log_info "Installing SELinux policy module..."
if ! semodule -i contact_enrichment.pp; then
    log_error "Failed to install policy module"
    exit 1
fi

log_info "Policy module installed successfully"

# Verify installation
log_info "Verifying policy installation..."
if semodule -l | grep -q "contact_enrichment"; then
    VERSION=$(semodule -l | grep contact_enrichment | awk '{print $2}')
    log_info "Policy verified: contact_enrichment $VERSION"
else
    log_error "Policy verification failed"
    exit 1
fi

# Set file contexts
log_info "Configuring file contexts..."

# Application binary
semanage fcontext -a -t contact_enrichment_exec_t \
    '/usr/local/bin/contact-enrichment' 2>/dev/null || \
semanage fcontext -m -t contact_enrichment_exec_t \
    '/usr/local/bin/contact-enrichment'

# Configuration directory
semanage fcontext -a -t contact_enrichment_conf_t \
    '/etc/contact-enrichment(/.*)'? 2>/dev/null || \
semanage fcontext -m -t contact_enrichment_conf_t \
    '/etc/contact-enrichment(/.*)?'

# Log directory
semanage fcontext -a -t contact_enrichment_log_t \
    '/var/log/contact-enrichment(/.*)'? 2>/dev/null || \
semanage fcontext -m -t contact_enrichment_log_t \
    '/var/log/contact-enrichment(/.*)?'

# Variable data directory
semanage fcontext -a -t contact_enrichment_var_t \
    '/var/lib/contact-enrichment(/.*)?  ' 2>/dev/null || \
semanage fcontext -m -t contact_enrichment_var_t \
    '/var/lib/contact-enrichment(/.*)?'

# Temporary directory
semanage fcontext -a -t contact_enrichment_tmp_t \
    '/tmp/contact-enrichment(/.*)?'  2>/dev/null || \
semanage fcontext -m -t contact_enrichment_tmp_t \
    '/tmp/contact-enrichment(/.*)?'

log_info "File contexts configured"

# Create directories with proper contexts
log_info "Creating application directories..."
mkdir -p /etc/contact-enrichment \
         /var/log/contact-enrichment \
         /var/lib/contact-enrichment \
         /tmp/contact-enrichment

# Set ownership (if contact-enrichment user exists)
if id "contact-enrichment" &>/dev/null; then
    chown contact-enrichment:contact-enrichment /etc/contact-enrichment \
                                                 /var/log/contact-enrichment \
                                                 /var/lib/contact-enrichment \
                                                 /tmp/contact-enrichment
    log_info "Directory ownership set to contact-enrichment user"
else
    log_warn "User 'contact-enrichment' not found. Please create the application user."
fi

# Restore SELinux contexts
log_info "Restoring SELinux contexts..."
restorecon -Rv /etc/contact-enrichment \
               /var/log/contact-enrichment \
               /var/lib/contact-enrichment \
               /tmp/contact-enrichment \
               2>&1 | grep -v "not relabeling"

log_info "Contexts restored"

# Verify file contexts
log_info "Verifying file contexts..."
echo ""
echo "Expected contexts:"
echo "  /etc/contact-enrichment: contact_enrichment_conf_t"
echo "  /var/log/contact-enrichment: contact_enrichment_log_t"
echo "  /var/lib/contact-enrichment: contact_enrichment_var_t"
echo ""
echo "Actual contexts:"
ls -lZd /etc/contact-enrichment
ls -lZd /var/log/contact-enrichment
ls -lZd /var/lib/contact-enrichment

# Create uninstall script
log_info "Creating uninstall script..."
cat > /usr/local/bin/contact-enrichment-selinux-uninstall.sh << 'UNINSTALL_SCRIPT'
#!/bin/bash
# Uninstall Contact Enrichment SELinux Policy
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

echo "Removing SELinux policy module..."
semodule -r contact_enrichment || echo "Module may not be installed"

echo "Removing file contexts..."
semanage fcontext -d '/usr/local/bin/contact-enrichment' 2>/dev/null || true
semanage fcontext -d '/etc/contact-enrichment(/.*)?'  2>/dev/null || true
semanage fcontext -d '/var/log/contact-enrichment(/.*)?' 2>/dev/null || true
semanage fcontext -d '/var/lib/contact-enrichment(/.*)?' 2>/dev/null || true
semanage fcontext -d '/tmp/contact-enrichment(/.*)?' 2>/dev/null || true

echo "Restoring default contexts..."
restorecon -Rv /etc/contact-enrichment \
               /var/log/contact-enrichment \
               /var/lib/contact-enrichment \
               /tmp/contact-enrichment \
               2>/dev/null || true

echo "SELinux policy uninstalled successfully"
UNINSTALL_SCRIPT

chmod +x /usr/local/bin/contact-enrichment-selinux-uninstall.sh
log_info "Uninstall script created: /usr/local/bin/contact-enrichment-selinux-uninstall.sh"

# Final summary
echo ""
log_info "============================================"
log_info "SELinux Policy Installation Complete!"
log_info "============================================"
echo ""
echo "  Policy Module: contact_enrichment (version $VERSION)"
echo "  Mode: $SELINUX_MODE"
echo ""
echo "Next Steps:"
echo "  1. Verify no SELinux denials: sudo ausearch -m avc -ts recent"
echo "  2. Deploy application binary to /usr/local/bin/contact-enrichment"
echo "  3. Start application and monitor: sudo journalctl -u contact-enrichment -f"
echo "  4. Check for denials during operation"
echo ""
echo "To uninstall:"
echo "  sudo /usr/local/bin/contact-enrichment-selinux-uninstall.sh"
echo ""

# Optional: Check for recent denials
if ausearch -m avc -ts recent 2>/dev/null | grep -q "contact_enrichment"; then
    log_warn "Recent SELinux denials detected for contact_enrichment"
    echo "Run: sudo ausearch -m avc -ts recent | grep contact_enrichment"
fi

exit 0
