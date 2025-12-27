// Contact repository implementation using SQLx with PostgreSQL
use crate::domain::contact::{Contact, EncryptedValue, SecurityLabel};
use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Row};
use std::sync::Arc;
use uuid::Uuid;

/// Repository interface for Contact aggregate.
#[async_trait]
pub trait ContactRepository: Send + Sync {
    async fn find_by_id(
        &self,
        id: Uuid,
        security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError>;

    async fn find_by_email_hash(
        &self,
        email_hash: &[u8],
        security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError>;

    async fn save(
        &self,
        contact: &Contact,
        security_context: &SecurityContext,
    ) -> Result<(), RepositoryError>;

    async fn delete(
        &self,
        id: Uuid,
        security_context: &SecurityContext,
    ) -> Result<(), RepositoryError>;

    async fn exists_by_email_hash(
        &self,
        email_hash: &[u8],
        security_context: &SecurityContext,
    ) -> Result<bool, RepositoryError>;
}

/// Security context for authorization.
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub request_id: Uuid,
    pub principal_id: Uuid,
    pub clearance: SecurityLabel,
    pub mfa_verified: bool,
    pub declared_purpose: Option<String>,
}

/// PostgreSQL repository implementation with Row-Level Security.
///
/// Security features:
/// - PostgreSQL RLS policies enforce MAC at database level
/// - Session variables set before each query for RLS context
/// - Optimistic locking via version column
/// - All operations logged for audit trail
pub struct PostgresContactRepository {
    pool: Arc<PgPool>,
}

impl PostgresContactRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Set PostgreSQL session variables for Row-Level Security.
    /// Human note: SET LOCAL is scoped to the current transaction/connection; always call this
    /// before queries within the same transaction so RLS policies see the correct context.
    async fn apply_security_context(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        // Set clearance levels for RLS
        let conf = context.clearance.confidentiality() as i32;
        let integ = context.clearance.integrity() as i32;
sqlx::query(&format!("SET app.clearance_conf = {}", conf))
            .execute(&mut **tx)
            .await?;
sqlx::query(&format!("SET app.clearance_integ = {}", integ))
            .execute(&mut **tx)
            .await?;

        // Set principal ID for audit
        let pid = context.principal_id.to_string();
sqlx::query(&format!("SET app.principal_id = '{}'", pid))
            .execute(&mut **tx)
            .await?;

        // Set compartments (comma-separated)
        let comps = context
            .clearance
            .compartments()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
sqlx::query(&format!("SET app.compartments = '{}'", comps))
            .execute(&mut **tx)
            .await?;

        tracing::debug!(
            principal_id = %context.principal_id,
            clearance = ?context.clearance,
            compartments = %comps,
            "Applied RLS context"
        );

        Ok(())
    }
}

#[async_trait]
impl ContactRepository for PostgresContactRepository {
    async fn find_by_id(
        &self,
        id: Uuid,
        security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        self.apply_security_context(&mut tx, security_context)
            .await?;

        let row = sqlx::query(
            r#"
            SELECT c.id,
                   c.canonical_email   AS canonical_email,
                   c.email_key_id      AS canonical_email_key_id,
                   c.email_algorithm   AS canonical_email_algorithm,
                   c.email_iv          AS canonical_email_iv,
                   c.email_auth_tag    AS canonical_email_auth_tag,
                   c.canonical_email_hash,
                   c.full_name         AS full_name,
                   c.name_key_id       AS full_name_key_id,
                   c.name_algorithm    AS full_name_algorithm,
                   c.name_iv           AS full_name_iv,
                   c.name_auth_tag     AS full_name_auth_tag,
                   c.confidentiality   AS confidentiality_level,
                   c.integrity         AS integrity_level,
                   (SELECT COALESCE(ARRAY(SELECT compartment FROM security_label_compartments s WHERE s.security_label_id = c.id), ARRAY[]::text[])) AS compartments,
                   c.created_at, c.created_by, c.updated_at, c.version
            FROM contacts c
            WHERE c.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        if let Some(row) = row {
            let contact = self.row_to_contact(row)?;
            tracing::info!(
                contact_id = %id,
                principal_id = %security_context.principal_id,
                "Contact retrieved"
            );
            Ok(Some(contact))
        } else {
            tracing::debug!(
                contact_id = %id,
                "Contact not found or access denied"
            );
            Ok(None)
        }
    }

    async fn find_by_email_hash(
        &self,
        email_hash: &[u8],
        security_context: &SecurityContext,
    ) -> Result<Option<Contact>, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        self.apply_security_context(&mut tx, security_context)
            .await?;

        let row = sqlx::query(
            r#"
            SELECT c.id,
                   c.canonical_email   AS canonical_email,
                   c.email_key_id      AS canonical_email_key_id,
                   c.email_algorithm   AS canonical_email_algorithm,
                   c.email_iv          AS canonical_email_iv,
                   c.email_auth_tag    AS canonical_email_auth_tag,
                   c.canonical_email_hash,
                   c.full_name         AS full_name,
                   c.name_key_id       AS full_name_key_id,
                   c.name_algorithm    AS full_name_algorithm,
                   c.name_iv           AS full_name_iv,
                   c.name_auth_tag     AS full_name_auth_tag,
                   c.confidentiality   AS confidentiality_level,
                   c.integrity         AS integrity_level,
                   (SELECT COALESCE(ARRAY(SELECT compartment FROM security_label_compartments s WHERE s.security_label_id = c.id), ARRAY[]::text[])) AS compartments,
                   c.created_at, c.created_by, c.updated_at, c.version
            FROM contacts c
            WHERE c.canonical_email_hash = $1
            "#,
        )
        .bind(email_hash)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        if let Some(row) = row {
            let contact = self.row_to_contact(row)?;
            tracing::info!(
                contact_id = %contact.id,
                principal_id = %security_context.principal_id,
                "Contact retrieved by email hash"
            );
            Ok(Some(contact))
        } else {
            Ok(None)
        }
    }

    async fn save(
        &self,
        contact: &Contact,
        security_context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        self.apply_security_context(&mut tx, security_context)
            .await?;

        if contact.version == 1 {
            // Insert new contact
            sqlx::query(
                r#"
                INSERT INTO contacts (
                    id, canonical_email, email_key_id,
                    email_algorithm, email_iv, email_auth_tag,
                    canonical_email_hash, full_name, name_key_id,
                    name_algorithm, name_iv, name_auth_tag,
                    confidentiality, integrity,
                    created_at, created_by, updated_at, version
                ) VALUES (
                    $1, $2, $3, $4, $5, $6,
                    $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18
                )
                "#,
            )
            .bind(contact.id)
            .bind(&contact.canonical_email.ciphertext)
            .bind(&contact.canonical_email.key_id)
            .bind(&contact.canonical_email.algorithm)
            .bind(&contact.canonical_email.iv)
            .bind(&contact.canonical_email.auth_tag)
            .bind(&contact.canonical_email_hash)
            .bind(contact.full_name.as_ref().map(|e| &e.ciphertext))
            .bind(contact.full_name.as_ref().map(|e| &e.key_id))
            .bind(contact.full_name.as_ref().map(|e| &e.algorithm))
            .bind(contact.full_name.as_ref().map(|e| &e.iv))
            .bind(contact.full_name.as_ref().map(|e| &e.auth_tag))
            .bind(format!("{}", match contact.security_label.confidentiality() { crate::domain::contact::ConfidentialityLevel::Public => "PUBLIC", crate::domain::contact::ConfidentialityLevel::Internal => "INTERNAL", crate::domain::contact::ConfidentialityLevel::Confidential => "CONFIDENTIAL", crate::domain::contact::ConfidentialityLevel::Restricted => "RESTRICTED" }))
            .bind(format!("{}", match contact.security_label.integrity() { crate::domain::contact::IntegrityLevel::Low => "LOW", crate::domain::contact::IntegrityLevel::Medium => "MEDIUM", crate::domain::contact::IntegrityLevel::High => "HIGH", crate::domain::contact::IntegrityLevel::Critical => "CRITICAL" }))
            .bind(contact.created_at)
            .bind(contact.created_by)
            .bind(contact.updated_at)
            .bind(contact.version)
            .execute(&mut *tx)
            .await?;

            // Insert compartments into collection table
            for comp in contact.security_label.compartments() {
                sqlx::query(
                    "INSERT INTO security_label_compartments (security_label_id, compartment) VALUES ($1, $2)"
                )
                .bind(contact.id)
                .bind(comp)
                .execute(&mut *tx)
                .await?;
            }

            tracing::info!(
                contact_id = %contact.id,
                principal_id = %security_context.principal_id,
                "Contact created"
            );
        } else {
            // Update existing contact (optimistic locking)
            let result = sqlx::query(
                r#"
                UPDATE contacts
                SET updated_at = $1, version = version + 1
                WHERE id = $2 AND version = $3
                "#,
            )
            .bind(contact.updated_at)
            .bind(contact.id)
            .bind(contact.version)
            .execute(&mut *tx)
            .await?;

            if result.rows_affected() == 0 {
                return Err(RepositoryError::OptimisticLockError);
            }

            tracing::info!(
                contact_id = %contact.id,
                version = contact.version,
                principal_id = %security_context.principal_id,
                "Contact updated"
            );
        }

        tx.commit().await?;
        Ok(())
    }

    async fn delete(
        &self,
        id: Uuid,
        security_context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        self.apply_security_context(&mut tx, security_context)
            .await?;

        sqlx::query("DELETE FROM contacts WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        tracing::warn!(
            contact_id = %id,
            principal_id = %security_context.principal_id,
            "Contact deleted"
        );

        Ok(())
    }

    async fn exists_by_email_hash(
        &self,
        email_hash: &[u8],
        security_context: &SecurityContext,
    ) -> Result<bool, RepositoryError> {
        let mut tx = self.pool.begin().await?;
        self.apply_security_context(&mut tx, security_context)
            .await?;

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM contacts WHERE canonical_email_hash = $1")
                .bind(email_hash)
                .fetch_one(&mut *tx)
                .await?;

        tx.commit().await?;

        Ok(count.0 > 0)
    }
}

impl PostgresContactRepository {
    fn row_to_contact(&self, row: sqlx::postgres::PgRow) -> Result<Contact, RepositoryError> {
        // This is a simplified version - in production would reconstruct full aggregate
        // including enriched attributes and consent records
        // Human note: map DB ints -> enums explicitly (no transmute) to avoid UB on invalid values
        Ok(Contact {
            id: row.get("id"),
            canonical_email: EncryptedValue {
                ciphertext: row.get("canonical_email"),
                key_id: row.get("canonical_email_key_id"),
                algorithm: row.get("canonical_email_algorithm"),
                iv: row.get("canonical_email_iv"),
                auth_tag: row.get("canonical_email_auth_tag"),
            },
            canonical_email_hash: row.get("canonical_email_hash"),
            full_name: None, // TODO: Reconstruct from full_name columns if present
            security_label: {
                // Columns store textual levels; map to enums
                let conf_txt: String = row.get("confidentiality_level");
                let integ_txt: String = row.get("integrity_level");
                let conf = match conf_txt.as_str() {
                    "PUBLIC" => crate::domain::contact::ConfidentialityLevel::Public,
                    "INTERNAL" => crate::domain::contact::ConfidentialityLevel::Internal,
                    "CONFIDENTIAL" => crate::domain::contact::ConfidentialityLevel::Confidential,
                    "RESTRICTED" => crate::domain::contact::ConfidentialityLevel::Restricted,
                    _ => crate::domain::contact::ConfidentialityLevel::Internal,
                };
                let integ = match integ_txt.as_str() {
                    "LOW" => crate::domain::contact::IntegrityLevel::Low,
                    "MEDIUM" => crate::domain::contact::IntegrityLevel::Medium,
                    "HIGH" => crate::domain::contact::IntegrityLevel::High,
                    "CRITICAL" => crate::domain::contact::IntegrityLevel::Critical,
                    _ => crate::domain::contact::IntegrityLevel::Medium,
                };
                let comps: Vec<String> = row.get("compartments");
                SecurityLabel::new(conf, integ, comps)
            },
            enriched_attributes: Vec::new(),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            updated_at: row.get("updated_at"),
            version: row.get("version"),
        })
    }
}

/// Repository errors.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Optimistic lock error: contact was modified by another transaction")]
    OptimisticLockError,

    #[error("Access denied")]
    AccessDenied,
}
