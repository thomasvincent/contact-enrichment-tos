// Contact repository implementation using SQLx with PostgreSQL
use crate::domain::contact::{Contact, EnrichedAttribute, EncryptedValue, SecurityLabel};
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
    async fn apply_security_context(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        context: &SecurityContext,
    ) -> Result<(), RepositoryError> {
        // Set clearance levels for RLS
        sqlx::query("SET LOCAL app.clearance_conf = $1")
            .bind(context.clearance.confidentiality as i32)
            .execute(&mut **tx)
            .await?;

        sqlx::query("SET LOCAL app.clearance_integ = $1")
            .bind(context.clearance.integrity as i32)
            .execute(&mut **tx)
            .await?;

        // Set principal ID for audit
        sqlx::query("SET LOCAL app.principal_id = $1")
            .bind(context.principal_id.to_string())
            .execute(&mut **tx)
            .await?;

        tracing::debug!(
            principal_id = %context.principal_id,
            clearance = ?context.clearance,
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
            SELECT id, canonical_email_ciphertext, canonical_email_key_id,
                   canonical_email_algorithm, canonical_email_iv, canonical_email_auth_tag,
                   canonical_email_hash, full_name_ciphertext, full_name_key_id,
                   full_name_algorithm, full_name_iv, full_name_auth_tag,
                   confidentiality_level, integrity_level, compartments, caveats,
                   created_at, created_by, updated_at, version
            FROM contacts
            WHERE id = $1
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
            SELECT id, canonical_email_ciphertext, canonical_email_key_id,
                   canonical_email_algorithm, canonical_email_iv, canonical_email_auth_tag,
                   canonical_email_hash, full_name_ciphertext, full_name_key_id,
                   full_name_algorithm, full_name_iv, full_name_auth_tag,
                   confidentiality_level, integrity_level, compartments, caveats,
                   created_at, created_by, updated_at, version
            FROM contacts
            WHERE canonical_email_hash = $1
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
                    id, canonical_email_ciphertext, canonical_email_key_id,
                    canonical_email_algorithm, canonical_email_iv, canonical_email_auth_tag,
                    canonical_email_hash, full_name_ciphertext, full_name_key_id,
                    full_name_algorithm, full_name_iv, full_name_auth_tag,
                    confidentiality_level, integrity_level, compartments, caveats,
                    created_at, created_by, updated_at, version
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                    $17, $18, $19, $20
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
            .bind(contact.security_label.confidentiality as i32)
            .bind(contact.security_label.integrity as i32)
            .bind(
                contact
                    .security_label
                    .compartments
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .bind(Vec::<String>::new()) // caveats
            .bind(contact.created_at)
            .bind(contact.created_by)
            .bind(contact.updated_at)
            .bind(contact.version)
            .execute(&mut *tx)
            .await?;

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
        Ok(Contact {
            id: row.get("id"),
            canonical_email: EncryptedValue {
                ciphertext: row.get("canonical_email_ciphertext"),
                key_id: row.get("canonical_email_key_id"),
                algorithm: row.get("canonical_email_algorithm"),
                iv: row.get("canonical_email_iv"),
                auth_tag: row.get("canonical_email_auth_tag"),
            },
            canonical_email_hash: row.get("canonical_email_hash"),
            full_name: None, // TODO: Reconstruct from row
            security_label: SecurityLabel {
                confidentiality: unsafe {
                    std::mem::transmute(row.get::<i32, _>("confidentiality_level"))
                },
                integrity: unsafe { std::mem::transmute(row.get::<i32, _>("integrity_level")) },
                compartments: row
                    .get::<Vec<String>, _>("compartments")
                    .into_iter()
                    .collect(),
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
