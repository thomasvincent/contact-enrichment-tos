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
}

#[tokio::test]
#[ignore = "requires PostgreSQL with appuser configured"]
async fn duplicate_email_hash_conflict() {
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

    let label = SecurityLabel::new(ConfidentialityLevel::Confidential, IntegrityLevel::High, vec!["PII".into()]);
    let ctx = SecurityContext { request_id: Uuid::new_v4(), principal_id: Uuid::new_v4(), clearance: label.clone(), mfa_verified: true, declared_purpose: Some("test".into()) };

    let contact1 = Contact::new(
        contact_enrichment_tos::domain::contact::EncryptedValue { ciphertext: b"a@example.com".to_vec(), key_id: "k1".into(), algorithm: "AES-256-GCM".into(), iv: Some(vec![0;12]), auth_tag: Some(vec![0;16]) },
        vec![1,2,3], None, label.clone(), Uuid::new_v4());

    repo.save(&contact1, &ctx).await.expect("first insert");

    let contact2 = Contact::new(
        contact_enrichment_tos::domain::contact::EncryptedValue { ciphertext: b"a@example.com".to_vec(), key_id: "k1".into(), algorithm: "AES-256-GCM".into(), iv: Some(vec![0;12]), auth_tag: Some(vec![0;16]) },
        vec![1,2,3], None, label.clone(), Uuid::new_v4());

    let err = repo.save(&contact2, &ctx).await.err().expect("should error on duplicate");
    match err {
        contact_enrichment_tos::infrastructure::repository::RepositoryError::DatabaseError(db) => {
            assert!(db.as_database_error().is_some(), "must be db error");
        }
        _ => panic!("unexpected error type"),
    }
}
