// REST API handlers for contact operations
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::contact::{AttributeType, ConfidentialityLevel, IntegrityLevel, SecurityLabel, Contact, EncryptedValue};
use crate::infrastructure::crypto::CryptoService;
use crate::infrastructure::repository::{ContactRepository, SecurityContext};
use crate::infrastructure::security::SecurityKernel;

/// Request to create a new contact.
#[derive(Debug, Deserialize)]
pub struct CreateContactRequest {
    pub email: String,
    pub full_name: Option<String>,
    pub confidentiality_level: String,
    pub integrity_level: String,
    pub compartments: Vec<String>,
}

/// Response after creating a contact.
#[derive(Debug, Serialize)]
pub struct CreateContactResponse {
    pub id: Uuid,
    pub created_at: String,
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
    crypto_service: web::Data<Arc<dyn CryptoService + Send + Sync>>,
    security_kernel: web::Data<Arc<dyn SecurityKernel + Send + Sync>>,
    repository: web::Data<Arc<dyn ContactRepository + Send + Sync>>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let ctx = security_context.into_inner();

    // Authorize operation
    if let Err(e) = security_kernel.authorize_contact_creation(&ctx) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": e.to_string()}));
    }

    // Map label
    let conf = match req.confidentiality_level.to_uppercase().as_str() {
        "PUBLIC" => ConfidentialityLevel::Public,
        "INTERNAL" => ConfidentialityLevel::Internal,
        "CONFIDENTIAL" => ConfidentialityLevel::Confidential,
        "RESTRICTED" => ConfidentialityLevel::Restricted,
        _ => ConfidentialityLevel::Internal,
    };
    let integ = match req.integrity_level.to_uppercase().as_str() {
        "LOW" => IntegrityLevel::Low,
        "MEDIUM" => IntegrityLevel::Medium,
        "HIGH" => IntegrityLevel::High,
        "CRITICAL" => IntegrityLevel::Critical,
        _ => IntegrityLevel::Medium,
    };
    let label = SecurityLabel::new(conf, integ, req.compartments.clone());

    // Encrypt email and optional full name
    let email_bytes = req.email.trim().to_lowercase().into_bytes();
    let encrypted_email = match crypto_service.encrypt(&email_bytes, "email-key") {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "encryption failed"}))
        }
    };
    let encrypted_name = if let Some(name) = &req.full_name {
        match crypto_service.encrypt(name.as_bytes(), "name-key") {
            Ok(v) => Some(v),
            Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "encryption failed"})),
        }
    } else { None };

    // Compute email hash
    let email_hash = crypto_service.hash(&email_bytes);

    // Check duplicates
    if let Ok(true) = repository
        .exists_by_email_hash(&email_hash, &ctx)
        .await
    {
        return HttpResponse::Conflict().json(serde_json::json!({"error": "contact exists"}));
    }

    // Build aggregate and persist
    let contact = Contact::new(encrypted_email, email_hash, encrypted_name, label, ctx.principal_id);
    if let Err(e) = repository.save(&contact, &ctx).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Created().json(CreateContactResponse {
        id: contact.id,
        created_at: contact.created_at.to_rfc3339(),
    })
}

/// Retrieve contact by ID.
pub async fn get_contact(
    contact_id: web::Path<Uuid>,
    repository: web::Data<Arc<dyn ContactRepository + Send + Sync>>,
    _crypto_service: web::Data<Arc<dyn CryptoService + Send + Sync>>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let id = contact_id.into_inner();

    match repository.find_by_id(id, &security_context).await {
        Ok(Some(contact)) => {
            // Human note: avoid decrypting PII in responses unless policy explicitly allows.
            HttpResponse::Ok().json(serde_json::json!({
                "id": contact.id,
                "created_at": contact.created_at.to_rfc3339(),
                "version": contact.version
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Contact not found or access denied"
        })),
        Err(e) => {
            tracing::error!("Failed to retrieve contact: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }))
        }
    }
}

/// Enrich a contact with additional attributes.
pub async fn enrich_contact(
    contact_id: web::Path<Uuid>,
    req: web::Json<EnrichContactRequest>,
    repository: web::Data<Arc<dyn ContactRepository + Send + Sync>>,
    crypto_service: web::Data<Arc<dyn CryptoService + Send + Sync>>,
    security_kernel: web::Data<Arc<dyn SecurityKernel + Send + Sync>>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let id = contact_id.into_inner();
    let ctx = security_context.into_inner();

    let contact_opt = match repository.find_by_id(id, &ctx).await {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut contact = if let Some(c) = contact_opt { c } else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
    };

    // Encrypt attribute value
    let enc = match crypto_service.encrypt(req.value.as_bytes(), "attr-key") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "encryption failed"})),
    };

    // For now, inherit contact label; production can create attribute label from request
    let attr_label = contact.security_label.clone();

    // Authorize enrichment
    if let Err(e) = security_kernel.authorize_enrichment(&ctx, &contact.security_label, &attr_label) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": e.to_string()}));
    }

    // Map attribute type
    let atype = match req.attribute_type.to_uppercase().as_str() {
        "FULLNAME" => AttributeType::FullName,
        "JOBTITLE" => AttributeType::JobTitle,
        "COMPANYNAME" => AttributeType::CompanyName,
        "PHONEWORK" => AttributeType::PhoneWork,
        "LINKEDINURL" => AttributeType::LinkedInUrl,
        _ => AttributeType::FullName,
    };

    if let Err(err) = contact.add_enrichment(atype, enc, Uuid::new_v4(), req.confidence_score, attr_label) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": err}));
    }

    if let Err(e) = repository.save(&contact, &ctx).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(serde_json::json!({"id": contact.id, "version": contact.version}))
}

/// Delete a contact (GDPR right to erasure).
pub async fn delete_contact(
    contact_id: web::Path<Uuid>,
    repository: web::Data<Arc<dyn ContactRepository + Send + Sync>>,
    _security_kernel: web::Data<Arc<dyn SecurityKernel + Send + Sync>>,
    security_context: web::ReqData<SecurityContext>,
) -> impl Responder {
    let id = contact_id.into_inner();
    let ctx = security_context.into_inner();

    if let Err(e) = repository.delete(id, &ctx).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

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
