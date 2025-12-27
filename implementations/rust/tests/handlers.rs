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
async fn create_and_get_contact_happy_path() {
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
                            .route("", web::post().to(handlers::create_contact))
                            .route("/{id}", web::get().to(handlers::get_contact)),
                    ),
            ),
    )
    .await;

    let payload = serde_json::json!({
        "email": "alice@example.com",
        "full_name": "Alice Example",
        "confidentiality_level": "CONFIDENTIAL",
        "integrity_level": "HIGH",
        "compartments": ["PII"]
    });

    let req = test::TestRequest::post()
        .uri("/api/v1/contacts")
        .set_json(&payload)
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let id = resp.get("id").unwrap().as_str().unwrap().to_string();

    let req_get = test::TestRequest::get()
        .uri(&format!("/api/v1/contacts/{}", id))
        .to_request();
    let resp_get = test::call_service(&app, req_get).await;
    assert!(resp_get.status().is_success());
}