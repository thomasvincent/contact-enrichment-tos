use std::{sync::Arc, time::Duration};

use contact_enrichment_tos::domain::contact::{ConfidentialityLevel, Contact, IntegrityLevel, SecurityLabel};
use contact_enrichment_tos::infrastructure::repository::{ContactRepository, PostgresContactRepository, SecurityContext};
use sqlx::postgres::PgPoolOptions;
use testcontainers::{clients::Cli, GenericImage};
use uuid::Uuid;

fn start_postgres() -> (testcontainers::Container<'static, GenericImage>, String) {
    let docker: &'static Cli = Box::leak(Box::new(Cli::default()));
    let image = GenericImage::new("postgres", "15-alpine")
        .with_env_var("POSTGRES_DB", "contact_enrichment")
        .with_env_var("POSTGRES_USER", "contact_enrichment")
        .with_env_var("POSTGRES_PASSWORD", "changeme")
        .with_wait_for(testcontainers::core::WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ));
    let container = docker.run(image);
    let host_port = container.get_host_port_ipv4(5432);
    let jdbc = format!(
        "postgres://contact_enrichment:changeme@127.0.0.1:{}/contact_enrichment",
        host_port
    );
    (container, jdbc)
}

async fn apply_migrations(pool: &sqlx::PgPool) {
    sqlx::migrate!("./migrations").run(pool).await.expect("run migrations");

    // Create appuser for RLS testing
    sqlx::query("CREATE USER appuser WITH PASSWORD 'app'")
        .execute(pool)
        .await
        .ok(); // Ignore error if user already exists

    sqlx::query("GRANT CONNECT ON DATABASE contact_enrichment TO appuser")
        .execute(pool)
        .await
        .ok();

    sqlx::query("GRANT USAGE ON SCHEMA public TO appuser")
        .execute(pool)
        .await
        .ok();

    sqlx::query("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser")
        .execute(pool)
        .await
        .ok();
}

#[tokio::test]
#[ignore = "contacts table schema requires migration"]
async fn delete_blocked_without_clearance_then_allowed_with_clearance() {
    let (_pg, url) = start_postgres();

    let admin_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&url)
        .await
        .expect("connect pg");
    apply_migrations(&admin_pool).await;

    let app_url = url.replace("contact_enrichment:changeme", "appuser:app");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&app_url)
        .await
        .expect("connect appuser");

    let repo = PostgresContactRepository::new(Arc::new(pool.clone()));

    let high = SecurityLabel::new(ConfidentialityLevel::Restricted, IntegrityLevel::Critical, vec!["PII".into()]);
    let low = SecurityLabel::new(ConfidentialityLevel::Internal, IntegrityLevel::Medium, vec![]);

    let writer_ctx = SecurityContext { request_id: Uuid::new_v4(), principal_id: Uuid::new_v4(), clearance: high.clone(), mfa_verified: true, declared_purpose: Some("test".into()) };
    let low_ctx = SecurityContext { request_id: Uuid::new_v4(), principal_id: Uuid::new_v4(), clearance: low.clone(), mfa_verified: true, declared_purpose: Some("test".into()) };

    let contact = Contact::new(
        contact_enrichment_tos::domain::contact::EncryptedValue { ciphertext: b"d@example.com".to_vec(), key_id: "k1".into(), algorithm: "AES-256-GCM".into(), iv: Some(vec![0;12]), auth_tag: Some(vec![0;16]) },
        vec![9,9,9], None, high.clone(), Uuid::new_v4());

    repo.save(&contact, &writer_ctx).await.expect("insert");

    // Attempt delete with low clearance should have no effect
    let _ = repo.delete(contact.id, &low_ctx).await;
    let still_there = repo.find_by_id(contact.id, &writer_ctx).await.expect("query").is_some();
    assert!(still_there, "low clearance delete should be blocked by RLS");

    // Delete with sufficient clearance
    repo.delete(contact.id, &writer_ctx).await.expect("delete");
    let gone = repo.find_by_id(contact.id, &writer_ctx).await.expect("query").is_none();
    assert!(gone, "row should be deleted by high clearance");
}
