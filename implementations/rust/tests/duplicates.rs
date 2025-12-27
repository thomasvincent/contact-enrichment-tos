use actix_web::{test, web, App};
use std::sync::Arc;

use contact_enrichment_tos::api::{handlers, middleware::SecurityContextMiddleware};
use contact_enrichment_tos::infrastructure::{
    crypto::{CryptoService, RingCryptoService},
    mem_repository::MemContactRepository,
    repository::ContactRepository,
    security::{SecurityKernel, TrustedSecurityKernel},
};

#[actix_rt::test]
async fn duplicate_create_conflict() {
    let crypto: Arc<dyn CryptoService + Send + Sync> = Arc::new(RingCryptoService::new());
    let kernel: Arc<dyn SecurityKernel + Send + Sync> = Arc::new(TrustedSecurityKernel::new());
    let repo: Arc<dyn ContactRepository + Send + Sync> = Arc::new(MemContactRepository::new());

    let app = test::init_service(
        App::new()
            .wrap(SecurityContextMiddleware)
            .app_data(web::Data::new(crypto.clone()))
            .app_data(web::Data::new(kernel.clone()))
            .app_data(web::Data::new(repo.clone()))
            .service(
                web::scope("/api/v1")
                    .service(
                        web::scope("/contacts")
                            .route("", web::post().to(handlers::create_contact)),
                    ),
            ),
    )
    .await;

    let payload = serde_json::json!({
        "email": "dup@example.com",
        "full_name": "Dup User",
        "confidentiality_level": "CONFIDENTIAL",
        "integrity_level": "HIGH",
        "compartments": ["PII"]
    });

    // First create
    let req1 = test::TestRequest::post().uri("/api/v1/contacts").set_json(&payload).to_request();
    let _ = test::call_service(&app, req1).await;

    // Second create should hit conflict
    let req2 = test::TestRequest::post().uri("/api/v1/contacts").set_json(&payload).to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(resp2.status().as_u16(), 409);
}
