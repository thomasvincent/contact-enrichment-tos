// Security middleware for extracting and validating security context
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};
use uuid::Uuid;

use crate::domain::contact::{ConfidentialityLevel, IntegrityLevel, SecurityLabel};
use crate::infrastructure::repository::SecurityContext;

/// Middleware to extract security context from request headers.
pub struct SecurityContextMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityContextMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityContextMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityContextMiddlewareService { service }))
    }
}

pub struct SecurityContextMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityContextMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract security context from headers
        let context = extract_security_context(&req);

        // Insert into request extensions
        req.extensions_mut().insert(context);

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Extract security context from request headers.
///
/// In production, this would:
/// 1. Validate JWT token
/// 2. Extract principal ID and clearance from token claims
/// 3. Verify MFA status
/// 4. Extract declared processing purpose
fn extract_security_context(req: &ServiceRequest) -> SecurityContext {
    // Mock implementation - in production would validate JWT
    use std::collections::HashSet;

    SecurityContext {
        request_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(), // Would come from JWT
        clearance: SecurityLabel {
            confidentiality: ConfidentialityLevel::Confidential,
            integrity: IntegrityLevel::High,
            compartments: HashSet::from(["PII".to_string()]),
        },
        mfa_verified: true, // Would come from JWT claims
        declared_purpose: Some("contact_enrichment".to_string()),
    }
}
