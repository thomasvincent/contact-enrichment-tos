// Security kernel for MAC enforcement
use crate::domain::contact::SecurityLabel;
use crate::infrastructure::repository::SecurityContext;

/// Security Kernel - Trusted Computing Base (TCB) for MAC enforcement.
///
/// Implements:
/// - Bell-LaPadula model (no read up)
/// - Biba model (no write down)
/// - Compartmentalization (need-to-know)
/// - Audit logging for all decisions
pub trait SecurityKernel: Send + Sync {
    /// Authorize read access (Bell-LaPadula: no read up).
    fn authorize_read(
        &self,
        context: &SecurityContext,
        data_label: &SecurityLabel,
    ) -> Result<(), SecurityError>;

    /// Authorize write access (Biba: no write down + Bell-LaPadula).
    fn authorize_write(
        &self,
        context: &SecurityContext,
        data_label: &SecurityLabel,
    ) -> Result<(), SecurityError>;

    /// Authorize contact creation.
    fn authorize_contact_creation(&self, context: &SecurityContext) -> Result<(), SecurityError>;

    /// Authorize enrichment operation.
    fn authorize_enrichment(
        &self,
        context: &SecurityContext,
        contact_label: &SecurityLabel,
        attribute_label: &SecurityLabel,
    ) -> Result<(), SecurityError>;
}

/// Trusted security kernel implementation.
pub struct TrustedSecurityKernel;

impl TrustedSecurityKernel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TrustedSecurityKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityKernel for TrustedSecurityKernel {
    fn authorize_read(
        &self,
        context: &SecurityContext,
        data_label: &SecurityLabel,
    ) -> Result<(), SecurityError> {
        // Bell-LaPadula: No read up
        // Human note: clearance must dominate data label (level + compartments). This prevents
        // accidental data leaks from higher classifications to lower-cleared principals.
        if !context.clearance.dominates(data_label) {
            tracing::warn!(
                principal_id = %context.principal_id,
                required_label = ?data_label,
                actual_clearance = ?context.clearance,
                "Authorization denied: insufficient clearance for read"
            );

            return Err(SecurityError::AccessDenied(
                "Your clearance does not dominate the data classification".to_string(),
            ));
        }

        // Check compartments (need-to-know)
        if !context
            .clearance
            .compartments()
            .is_superset(data_label.compartments())
        {
            tracing::warn!(
                principal_id = %context.principal_id,
required_compartments = ?data_label.compartments(),
                actual_compartments = ?context.clearance.compartments(),
                "Authorization denied: missing compartments"
            );

            return Err(SecurityError::AccessDenied(
                "Missing required compartments (need-to-know)".to_string(),
            ));
        }

        tracing::info!(
            principal_id = %context.principal_id,
            operation = "READ",
            "Authorization granted"
        );

        Ok(())
    }

    fn authorize_write(
        &self,
        context: &SecurityContext,
        data_label: &SecurityLabel,
    ) -> Result<(), SecurityError> {
        // Biba: No write down (integrity)
        if data_label.integrity() > context.clearance.integrity() {
            tracing::warn!(
                principal_id = %context.principal_id,
                required_integrity = ?data_label.integrity(),
                actual_integrity = ?context.clearance.integrity(),
                "Authorization denied: insufficient integrity for write"
            );

            return Err(SecurityError::AccessDenied(
                "Cannot write to higher integrity level (no write down)".to_string(),
            ));
        }

        // Must also be able to read (Bell-LaPadula)
        self.authorize_read(context, data_label)?;

        tracing::info!(
            principal_id = %context.principal_id,
            operation = "WRITE",
            "Authorization granted"
        );

        Ok(())
    }

    fn authorize_contact_creation(&self, context: &SecurityContext) -> Result<(), SecurityError> {
        use crate::domain::contact::IntegrityLevel;

        // Require minimum Medium integrity for contact creation
        if context.clearance.integrity() < IntegrityLevel::Medium {
            tracing::warn!(
                principal_id = %context.principal_id,
                actual_integrity = ?context.clearance.integrity(),
                "Authorization denied: insufficient integrity for contact creation"
            );

            return Err(SecurityError::AccessDenied(
                "Minimum Medium integrity level required for contact creation".to_string(),
            ));
        }

        // Require MFA for sensitive operations
        if !context.mfa_verified {
            tracing::warn!(
                principal_id = %context.principal_id,
                "Authorization denied: MFA required"
            );

            return Err(SecurityError::MfaRequired);
        }

        // Require declared purpose for GDPR/CCPA compliance
        if context.declared_purpose.is_none() {
            tracing::warn!(
                principal_id = %context.principal_id,
                "Authorization denied: no processing purpose declared"
            );

            return Err(SecurityError::AccessDenied(
                "Processing purpose must be declared (GDPR compliance)".to_string(),
            ));
        }

        tracing::info!(
            principal_id = %context.principal_id,
            operation = "CREATE_CONTACT",
            "Authorization granted"
        );

        Ok(())
    }

    fn authorize_enrichment(
        &self,
        context: &SecurityContext,
        contact_label: &SecurityLabel,
        attribute_label: &SecurityLabel,
    ) -> Result<(), SecurityError> {
        // Must be able to write to contact
        self.authorize_write(context, contact_label)?;

        // Attribute label must not exceed contact label (prevent upgrade)
        if !contact_label.dominates(attribute_label) {
            tracing::warn!(
                principal_id = %context.principal_id,
                contact_label = ?contact_label,
                attribute_label = ?attribute_label,
                "Authorization denied: attribute label exceeds contact label"
            );

            return Err(SecurityError::AccessDenied(
                "Attribute security label exceeds contact label".to_string(),
            ));
        }

        tracing::info!(
            principal_id = %context.principal_id,
            operation = "ENRICH",
            "Authorization granted"
        );

        Ok(())
    }
}

/// Security errors.
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Multi-factor authentication required")]
    MfaRequired,

    #[error("Session expired")]
    SessionExpired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::contact::{ConfidentialityLevel, IntegrityLevel};
    use std::collections::HashSet;
    use uuid::Uuid;

    #[test]
    fn test_authorize_read_with_sufficient_clearance() {
        let kernel = TrustedSecurityKernel::new();

        let context = SecurityContext {
            request_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            clearance: SecurityLabel::new(
                ConfidentialityLevel::Confidential,
                IntegrityLevel::High,
                vec!["PII".to_string()],
            ),
            mfa_verified: true,
            declared_purpose: Some("testing".to_string()),
        };

        let data_label = SecurityLabel::new(
            ConfidentialityLevel::Internal,
            IntegrityLevel::Medium,
            vec![]
        );

        assert!(kernel.authorize_read(&context, &data_label).is_ok());
    }

    #[test]
    fn test_authorize_read_fails_with_insufficient_clearance() {
        let kernel = TrustedSecurityKernel::new();

        let context = SecurityContext {
            request_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            clearance: SecurityLabel::new(
                ConfidentialityLevel::Internal,
                IntegrityLevel::Medium,
                vec![]
            ),
            mfa_verified: true,
            declared_purpose: Some("testing".to_string()),
        };

        let data_label = SecurityLabel::new(
            ConfidentialityLevel::Confidential,
            IntegrityLevel::High,
            vec!["PII".to_string()]
        );

        assert!(kernel.authorize_read(&context, &data_label).is_err());
    }
}
