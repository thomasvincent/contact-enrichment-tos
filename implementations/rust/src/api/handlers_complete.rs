// Complete REST API handlers for contact operations
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::contact::{
    AttributeType, ConfidentialityLevel, Contact, EncryptedValue, IntegrityLevel, SecurityLabel,
};
use crate::infrastructure::crypto::CryptoService;
use crate::infrastructure::repository::{ContactRepository, SecurityContext};
use crate::infrastructure::security::SecurityKernel;

/// Application state.
pub struct AppState {
    pub repository: Arc<dyn ContactRepository>,
    pub crypto_service: Arc<dyn CryptoService>,
    pub security_kernel: Arc<dyn SecurityKernel>,
}

/// Request to create a new contact.
#[derive(Debug, Deserialize)]
pub struct CreateContactRequest {
    pub email: String,
    pub full_name: Option<String>,
    pub confidentiality_level: String,
    pub integrity_level: String,
    pub compartments: Vec<String>,
    pub processing_purpose: String,
    pub consent_granted: bool,
}

/// Response after creating a contact.
#[derive(Debug, Serialize)]
pub struct ContactResponse {
    pub id: Uuid,
    pub email: Option<String>, // Decrypted if authorized
    pub full_name: Option<String>,
    pub security_label: SecurityLabelDto,
    pub created_at: String,
    pub version: i64,
}

#[derive(Debug, Serialize)]
pub struct SecurityLabelDto {
    pub confidentiality_level: String,
    pub integrity_level: String,
    pub compartments: Vec<String>,
}

/// Request to enrich a contact.
#[derive(Debug, Deserialize)]
pub struct EnrichContactRequest {
    pub attribute_type: String,
    pub value: String,
    pub confidence_score: f64,
    pub provenance_source: String,
}

/// Create a new contact.
pub async fn create_contact(
    req: web::Json<CreateContactRequest>,
    state: web::Data<AppState>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let context = security_context.into_inner();

    tracing::info!("Creating contact with email: {}", mask_email(&req.email));

    // Authorize operation
    if let Err(e) = state
        .security_kernel
        .authorize_contact_creation(&context)
    {
        tracing::warn!("Authorization failed: {}", e);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied",
            "message": e.to_string()
        }));
    }

    // Encrypt email
    let email_bytes = req.email.as_bytes();
    let encrypted_email = match state.crypto_service.encrypt(email_bytes, "email-key") {
        Ok(enc) => enc,
        Err(e) => {
            tracing::error!("Encryption failed: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    };

    // Compute email hash
    let email_hash = state.crypto_service.hash(email_bytes);

    // Check if contact already exists
    match state
        .repository
        .exists_by_email_hash(&email_hash, &context)
        .await
    {
        Ok(true) => {
            return HttpResponse::Conflict().json(serde_json::json!({
                "error": "Contact already exists with this email"
            }));
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    }

    // Encrypt full name if provided
    let encrypted_full_name = if let Some(full_name) = &req.full_name {
        match state
            .crypto_service
            .encrypt(full_name.as_bytes(), "name-key")
        {
            Ok(enc) => Some(enc),
            Err(e) => {
                tracing::error!("Encryption failed: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error"
                }));
            }
        }
    } else {
        None
    };

    // Parse security label
    let confidentiality = match req.confidentiality_level.as_str() {
        "PUBLIC" => ConfidentialityLevel::Public,
        "INTERNAL" => ConfidentialityLevel::Internal,
        "CONFIDENTIAL" => ConfidentialityLevel::Confidential,
        "RESTRICTED" => ConfidentialityLevel::Restricted,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid confidentiality level"
            }));
        }
    };

    let integrity = match req.integrity_level.as_str() {
        "LOW" => IntegrityLevel::Low,
        "MEDIUM" => IntegrityLevel::Medium,
        "HIGH" => IntegrityLevel::High,
        "CRITICAL" => IntegrityLevel::Critical,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid integrity level"
            }));
        }
    };

    let security_label = SecurityLabel {
        confidentiality,
        integrity,
        compartments: req.compartments.iter().cloned().collect(),
    };

    // Create contact aggregate
    let contact = Contact::new(
        encrypted_email,
        email_hash.clone(),
        encrypted_full_name,
        security_label.clone(),
        context.principal_id,
    );

    // Persist
    if let Err(e) = state.repository.save(&contact, &context).await {
        tracing::error!("Failed to save contact: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }));
    }

    tracing::info!("Contact created successfully: id={}", contact.id);

    // Map to response (email is encrypted, don't decrypt in response for creation)
    let response = ContactResponse {
        id: contact.id,
        email: None,
        full_name: None,
        security_label: SecurityLabelDto {
            confidentiality_level: format!("{:?}", security_label.confidentiality),
            integrity_level: format!("{:?}", security_label.integrity),
            compartments: security_label.compartments.iter().cloned().collect(),
        },
        created_at: contact.created_at.to_rfc3339(),
        version: contact.version,
    };

    HttpResponse::Created().json(response)
}

/// Retrieve contact by ID.
pub async fn get_contact(
    contact_id: web::Path<Uuid>,
    state: web::Data<AppState>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let id = contact_id.into_inner();
    let context = security_context.into_inner();

    tracing::info!("Retrieving contact: id={}", id);

    let contact = match state.repository.find_by_id(id, &context).await {
        Ok(Some(contact)) => contact,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Contact not found or access denied"
            }));
        }
        Err(e) => {
            tracing::error!("Failed to retrieve contact: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    };

    // Authorize read access
    if let Err(e) = state
        .security_kernel
        .authorize_read(&context, &contact.security_label)
    {
        tracing::warn!("Authorization failed for read: {}", e);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied",
            "message": e.to_string()
        }));
    }

    // Decrypt email
    let email = match state.crypto_service.decrypt(&contact.canonical_email) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).to_string()),
        Err(e) => {
            tracing::warn!("Failed to decrypt email: {}", e);
            None
        }
    };

    // Decrypt full name if present
    let full_name = if let Some(ref enc_name) = contact.full_name {
        match state.crypto_service.decrypt(enc_name) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).to_string()),
            Err(e) => {
                tracing::warn!("Failed to decrypt full name: {}", e);
                None
            }
        }
    } else {
        None
    };

    let response = ContactResponse {
        id: contact.id,
        email,
        full_name,
        security_label: SecurityLabelDto {
            confidentiality_level: format!("{:?}", contact.security_label.confidentiality),
            integrity_level: format!("{:?}", contact.security_label.integrity),
            compartments: contact
                .security_label
                .compartments
                .iter()
                .cloned()
                .collect(),
        },
        created_at: contact.created_at.to_rfc3339(),
        version: contact.version,
    };

    HttpResponse::Ok().json(response)
}

/// Delete a contact (GDPR right to erasure).
pub async fn delete_contact(
    contact_id: web::Path<Uuid>,
    state: web::Data<AppState>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let id = contact_id.into_inner();
    let context = security_context.into_inner();

    tracing::warn!("Deleting contact: id={}", id);

    // Load contact to check authorization
    let contact = match state.repository.find_by_id(id, &context).await {
        Ok(Some(contact)) => contact,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Contact not found"
            }));
        }
        Err(e) => {
            tracing::error!("Failed to retrieve contact: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    };

    // Authorize write access (required for deletion)
    if let Err(e) = state
        .security_kernel
        .authorize_write(&context, &contact.security_label)
    {
        tracing::warn!("Authorization failed for delete: {}", e);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied",
            "message": e.to_string()
        }));
    }

    // Delete
    if let Err(e) = state.repository.delete(id, &context).await {
        tracing::error!("Failed to delete contact: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }));
    }

    tracing::warn!("Contact deleted successfully: id={}", id);

    HttpResponse::NoContent().finish()
}

/// Health check endpoint.
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "contact-enrichment-tos",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Mask email for logging (security).
fn mask_email(email: &str) -> String {
    if email.len() < 3 {
        return "***".to_string();
    }
    if let Some(at_index) = email.find('@') {
        format!("{}***{}", &email[..1], &email[at_index..])
    } else {
        format!("{}***", &email[..1])
    }
}
