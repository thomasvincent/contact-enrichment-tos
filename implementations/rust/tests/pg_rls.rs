use std::{path::PathBuf, sync::Arc, time::Duration};

use contact_enrichment_tos::domain::contact::{ConfidentialityLevel, Contact, EncryptedValue, IntegrityLevel, SecurityLabel};
use contact_enrichment_tos::infrastructure::repository::{ContactRepository, PostgresContactRepository, SecurityContext};
use sqlx::{postgres::PgPoolOptions, PgPool};
use testcontainers::{clients::Cli, GenericImage};
use uuid::Uuid;

fn migrations_dir() -> PathBuf {
    // tests run from the crate dir; java migrations are at ../../java/src/main/resources/db/migration
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // implementations/rust -> implementations
    p.push("java/src/main/resources/db/migration");
    p
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut buf = String::new();
    let mut in_dollar = false;
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            if let Some('$') = chars.peek().copied() {
                in_dollar = !in_dollar;
            }
            buf.push(ch);
            continue;
        }
        if ch == ';' && !in_dollar {
            let trimmed = buf.trim();
            if !trimmed.is_empty() {
                stmts.push(trimmed.to_string());
            }
            buf.clear();
        } else {
            buf.push(ch);
        }
    }
    let trimmed = buf.trim();
    if !trimmed.is_empty() {
        stmts.push(trimmed.to_string());
    }
    stmts
}

async fn apply_migrations(pool: &PgPool) {
    // Use SQLx migrations under implementations/rust/migrations
    sqlx::migrate!("./migrations").run(pool).await.expect("run migrations");
}

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

fn enc_value(bytes: &[u8]) -> EncryptedValue {
    EncryptedValue {
        ciphertext: bytes.to_vec(),
        key_id: "k1".to_string(),
        algorithm: "AES-256-GCM".to_string(),
        iv: Some(vec![0u8; 12]),
        auth_tag: Some(vec![0u8; 16]),
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with appuser configured"]
async fn rls_allows_read_with_compartments_and_blocks_without() {
    let (_pg, url) = start_postgres();

    let admin_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&url)
        .await
        .expect("connect pg");

    apply_migrations(&admin_pool).await;

    // Connect as non-superuser app role to ensure RLS is enforced
    let app_url = url.replace("contact_enrichment:changeme", "appuser:app");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&app_url)
        .await
        .expect("connect appuser");

    let repo = PostgresContactRepository::new(Arc::new(pool.clone()));

    // Row label: CONFIDENTIAL/HIGH with PII compartment
    let row_label = SecurityLabel::new(ConfidentialityLevel::Confidential, IntegrityLevel::High, vec!["PII".into()]);

    let mut contact = Contact::new(enc_value(b"alice@example.com"), vec![1, 2, 3], None, row_label.clone(), Uuid::new_v4());

    let writer_ctx = SecurityContext {
        request_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
        clearance: row_label.clone(),
        mfa_verified: true,
        declared_purpose: Some("test".into()),
    };

    repo.save(&contact, &writer_ctx).await.expect("insert contact");

    // Allowed reader: same clearance
    let allowed = repo
        .find_by_id(contact.id, &writer_ctx)
        .await
        .expect("query")
        .is_some();
    assert!(allowed, "reader with PII should see the row");

    // Denied: lower clearance
    let low_ctx = SecurityContext {
        request_id: Uuid::new_v4(),
        principal_id: Uuid::new_v4(),
        clearance: SecurityLabel::new(ConfidentialityLevel::Internal, IntegrityLevel::Medium, vec![]),
        mfa_verified: true,
        declared_purpose: Some("test".into()),
    };

    let denied = repo
        .find_by_id(contact.id, &low_ctx)
        .await
        .expect("query")
        .is_none();
    assert!(denied, "reader without sufficient clearance should be blocked by RLS");
}
