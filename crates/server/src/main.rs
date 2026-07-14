//! Dalang SSO server entrypoint.
//!
//! Architecture at a glance:
//!   * Stateless HTTP layer (axum/tokio) — any node serves any request, so the
//!     tier scales horizontally behind a load balancer.
//!   * Access/id tokens are self-verifying RS256 JWTs (no DB read to validate);
//!     only refresh tokens and client records touch storage.
//!   * Storage is a runtime-selected sqlx `Any` pool (SQLite by default).
//!
//! These three properties are what the "100M concurrent users" target rests on:
//! push read-heavy verification to stateless JWTs and scale nodes + DB replicas.

mod assets;
mod config;
mod crypto;
mod db;
mod error;
mod models;
mod oauth;
mod signing;
mod state;
mod web;

use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use config::Config;
use db::Db;
use signing::Signer;
use state::AppState;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sso_server=debug".into()),
        )
        .init();

    let config = Config::from_env()?;
    warn_on_insecure_defaults(&config);

    let db = Db::connect(&config.database_url, config.database_max_connections).await?;
    if db.count_admins().await? == 0 {
        tracing::info!(
            "no admin yet — open {}/setup to create the super admin",
            config.issuer()
        );
    }

    let signer = Signer::from_config(
        &config.token_signing_alg,
        config.jwt_private_key_path.as_deref(),
    )?;

    let bind = config.bind_addr.clone();
    let state = AppState::new(config, db, signer);

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/dashboard") }))
        .route("/health", get(|| async { "ok" }))
        .merge(assets::router())
        .merge(oauth::router())
        .merge(web::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "Dalang SSO listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn warn_on_insecure_defaults(config: &Config) {
    if config.session_secret.starts_with("dev-insecure") {
        tracing::warn!("SSO_SESSION_SECRET is a dev default — set a strong secret for production");
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
