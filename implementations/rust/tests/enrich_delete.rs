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
async fn enrich_then_delete() {
let app = test::init_service(App::new()
        .wrap(SecurityContextMiddleware)
        .configure(|cfg| {
        let crypto: Arc<dyn CryptoService + Send + Sync> = Arc::new(RingCryptoService::new());
        let kernel: Arc<dyn SecurityKernel + Send + Sync> = Arc::new(TrustedSecurityKernel::new());
        let repo: Arc<dyn ContactRepository + Send + Sync> = Arc::new(MemContactRepository::new());
        cfg.app_data(web::Data::new(crypto.clone()))
            .app_data(web::Data::new(kernel.clone()))
            .app_data(web::Data::new(repo.clone()))
            .service(
                web::scope("/api/v1")
                    .service(
                        web::scope("/contacts")
                            .route("", web::post().to(handlers::create_contact))
                            .route("/{id}", web::get().to(handlers::get_contact))
                            .route("/{id}/enrich", web::post().to(handlers::enrich_contact))
                            .route("/{id}", web::delete().to(handlers::delete_contact)),
                    ),
            );
    })).await;

    // Create
    let payload = serde_json::json!({
        "email": "bob@example.com",
        "full_name": "Bob Example",
        "confidentiality_level": "CONFIDENTIAL",
        "integrity_level": "HIGH",
        "compartments": ["PII"]
    });
    let req = test::TestRequest::post().uri("/api/v1/contacts").set_json(&payload).to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let id = resp.get("id").unwrap().as_str().unwrap().to_string();

    // Enrich
    let enrich = serde_json::json!({
        "attribute_type": "FullName",
        "value": "Robert Example",
        "confidence_score": 0.8,
        "provenance_source": "manual"
    });
    let req_enrich = test::TestRequest::post()
        .uri(&format!("/api/v1/contacts/{}/enrich", id))
        .set_json(&enrich)
        .to_request();
    let resp_enrich = test::call_service(&app, req_enrich).await;
    assert!(resp_enrich.status().is_success());

    // Delete
    let req_delete = test::TestRequest::delete()
        .uri(&format!("/api/v1/contacts/{}", id))
        .to_request();
    let resp_delete = test::call_service(&app, req_delete).await;
    assert_eq!(resp_delete.status().as_u16(), 204);
}
