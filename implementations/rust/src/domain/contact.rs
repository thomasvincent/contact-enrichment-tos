// Contact aggregate root - Rust implementation
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

/// Confidentiality levels for MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidentialityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

/// Integrity levels for Biba model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Immutable security label for MAC enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLabel {
    confidentiality: ConfidentialityLevel,
    integrity: IntegrityLevel,
    compartments: HashSet<String>,
}

impl SecurityLabel {
    pub fn new(
        confidentiality: ConfidentialityLevel,
        integrity: IntegrityLevel,
        compartments: Vec<String>,
    ) -> Self {
        Self {
            confidentiality,
            integrity,
            compartments: compartments.into_iter().collect(),
        }
    }

    pub fn confidential_pii() -> Self {
        Self::new(
            ConfidentialityLevel::Confidential,
            IntegrityLevel::High,
            vec!["PII".to_string()],
        )
    }

    /// Check if this label dominates (can access) another label.
    pub fn dominates(&self, other: &SecurityLabel) -> bool {
        self.confidentiality >= other.confidentiality
            && self.integrity >= other.integrity
            && other.compartments.is_subset(&self.compartments)
    }
}

/// Encrypted value with metadata.
#[derive(Debug, Clone)]
pub struct EncryptedValue {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub iv: Option<Vec<u8>>,
    pub auth_tag: Option<Vec<u8>>,
}

/// Attribute types for enrichment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeType {
    FullName,
    JobTitle,
    CompanyName,
    PhoneWork,
    LinkedInUrl,
}

/// Enriched attribute with temporal validity.
#[derive(Debug, Clone)]
pub struct EnrichedAttribute {
    pub id: Uuid,
    pub attribute_type: AttributeType,
    pub encrypted_value: EncryptedValue,
    pub provenance_id: Uuid,
    pub confidence_score: f64,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub security_label: SecurityLabel,
}

impl EnrichedAttribute {
    pub fn supersede(&mut self, superseded_at: DateTime<Utc>) -> Result<(), String> {
        if self.valid_until.is_some() {
            return Err("Attribute already superseded".to_string());
        }
        self.valid_until = Some(superseded_at);
        Ok(())
    }
}

/// Contact aggregate root.
pub struct Contact {
    pub id: Uuid,
    pub canonical_email: EncryptedValue,
    pub canonical_email_hash: Vec<u8>,
    pub full_name: Option<EncryptedValue>,
    pub security_label: SecurityLabel,
    pub enriched_attributes: Vec<EnrichedAttribute>,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
}

impl Contact {
    pub fn new(
        canonical_email: EncryptedValue,
        email_hash: Vec<u8>,
        full_name: Option<EncryptedValue>,
        security_label: SecurityLabel,
        created_by: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            canonical_email,
            canonical_email_hash: email_hash,
            full_name,
            security_label,
            enriched_attributes: Vec::new(),
            created_at: now,
            created_by,
            updated_at: now,
            version: 1,
        }
    }

    pub fn add_enrichment(
        &mut self,
        attribute_type: AttributeType,
        encrypted_value: EncryptedValue,
        provenance_id: Uuid,
        confidence_score: f64,
        attribute_label: SecurityLabel,
    ) -> Result<(), String> {
        // Validate security label
        if !self.security_label.dominates(&attribute_label) {
            return Err("Attribute security label exceeds contact label".to_string());
        }

        // Supersede existing current attributes of same type
        let now = Utc::now();
        for attr in &mut self.enriched_attributes {
            if attr.attribute_type == attribute_type && attr.valid_until.is_none() {
                attr.supersede(now)?;
            }
        }

        // Add new attribute
        let new_attr = EnrichedAttribute {
            id: Uuid::new_v4(),
            attribute_type,
            encrypted_value,
            provenance_id,
            confidence_score,
            valid_from: now,
            valid_until: None,
            security_label: attribute_label,
        };

        self.enriched_attributes.push(new_attr);
        self.updated_at = now;

        Ok(())
    }

    pub fn get_current_attributes(&self) -> Vec<&EnrichedAttribute> {
        self.enriched_attributes
            .iter()
            .filter(|attr| attr.valid_until.is_none())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_label_dominance() {
        let high = SecurityLabel::confidential_pii();
        let low = SecurityLabel::new(
            ConfidentialityLevel::Internal,
            IntegrityLevel::Medium,
            vec![],
        );

        assert!(high.dominates(&low));
        assert!(!low.dominates(&high));
    }

    #[test]
    fn test_contact_creation() {
        let email = EncryptedValue {
            ciphertext: vec![1, 2, 3],
            key_id: "test-key".to_string(),
            algorithm: "AES-256-GCM".to_string(),
            iv: Some(vec![4, 5, 6]),
            auth_tag: Some(vec![7, 8, 9]),
        };

        let contact = Contact::new(
            email,
            vec![10, 11, 12],
            None,
            SecurityLabel::confidential_pii(),
            Uuid::new_v4(),
        );

        assert_eq!(contact.version, 1);
        assert!(contact.enriched_attributes.is_empty());
    }
}
