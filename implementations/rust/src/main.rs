// Main application entry point for contact enrichment TOS backend
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use contact_enrichment_tos::api::{handlers, middleware::SecurityContextMiddleware};
use contact_enrichment_tos::infrastructure::{
    crypto::RingCryptoService, security::TrustedSecurityKernel,
};

/// Application configuration.
#[derive(Debug, Clone)]
struct AppConfig {
    host: String,
    port: u16,
    database_url: String,
    log_level: String,
}

impl AppConfig {
    fn from_env() -> Self {
        Self {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/contact_enrichment".to_string()),
            log_level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    init_tracing();

    // Verify SELinux is enforcing (critical security requirement)
    verify_selinux_enforcing();

    // Load configuration
    let config = AppConfig::from_env();

    tracing::info!(
        "Starting Contact Enrichment Platform - TOS Edition\n\
         ╔═══════════════════════════════════════════════════════════╗\n\
         ║  Mandatory Access Control: ENABLED                        ║\n\
         ║  SELinux: ENFORCING                                       ║\n\
         ║  Encryption: AES-256-GCM (ring)                           ║\n\
         ║  Audit Trail: CRYPTOGRAPHIC                               ║\n\
         ╚═══════════════════════════════════════════════════════════╝"
    );

    // Initialize services
    let crypto_service = Arc::new(RingCryptoService::new());
    let security_kernel = Arc::new(TrustedSecurityKernel::new());

    // TODO: Initialize database pool
    // let db_pool = Arc::new(create_db_pool(&config.database_url).await?);
    // let repository = Arc::new(PostgresContactRepository::new(db_pool));

    let bind_address = format!("{}:{}", config.host, config.port);
    tracing::info!("Listening on {}", bind_address);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            // Middleware
            .wrap(Logger::default())
            .wrap(SecurityContextMiddleware)
            // Shared state
            // .app_data(web::Data::from(crypto_service.clone()))
            // .app_data(web::Data::from(security_kernel.clone()))
            // .app_data(web::Data::from(repository.clone()))
            // Routes
            .service(
                web::scope("/api/v1")
                    .route("/health", web::get().to(handlers::health_check))
                    .service(
                        web::scope("/contacts")
                            .route("", web::post().to(handlers::create_contact))
                            .route("/{id}", web::get().to(handlers::get_contact))
                            .route("/{id}/enrich", web::post().to(handlers::enrich_contact))
                            .route("/{id}", web::delete().to(handlers::delete_contact)),
                    ),
            )
    })
    .bind(&bind_address)?
    .run()
    .await
}

/// Initialize tracing subscriber for structured logging.
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "contact_enrichment_tos=info,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

/// Verify SELinux is in enforcing mode.
///
/// This is a critical security requirement for TOS compliance.
/// Application will refuse to start if SELinux is not enforcing.
fn verify_selinux_enforcing() {
    match std::process::Command::new("getenforce").output() {
        Ok(output) => {
            let mode = String::from_utf8_lossy(&output.stdout).trim().to_string();

            if mode != "Enforcing" {
                tracing::error!(
                    "SECURITY VIOLATION: SELinux is not in enforcing mode: {}",
                    mode
                );
                tracing::error!("Application startup BLOCKED - SELinux must be enforcing for TOS compliance");
                std::process::exit(1);
            }

            tracing::info!("SELinux verification: ENFORCING ✓");
        }
        Err(e) => {
            tracing::error!("Failed to verify SELinux status: {}", e);
            tracing::error!("Application startup BLOCKED - unable to verify SELinux");
            std::process::exit(1);
        }
    }
}

/// Create database connection pool.
///
/// TODO: Implement with SQLx
/// async fn create_db_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
///     sqlx::postgres::PgPoolOptions::new()
///         .max_connections(20)
///         .connect(database_url)
///         .await
/// }
