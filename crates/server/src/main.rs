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
mod site;
mod state;
mod web;

use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;
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
    // Fail closed on insecure defaults when exposed beyond loopback.
    config.validate()?;

    let db = Db::connect(&config.database_url, config.database_max_connections).await?;
    // Guarantee at least one tenant exists (covers upgrades of instances
    // onboarded before multi-tenancy). Idempotent: only creates if none.
    db.ensure_default_tenant().await?;
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
        .route("/health", get(|| async { "ok" }))
        .merge(site::router())
        .merge(assets::router())
        .merge(oauth::router())
        .merge(web::router())
        .layer(axum::middleware::map_response(security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "Dalang SSO listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Attach defensive security headers to every response. `frame-ancestors 'none'`
/// (plus `X-Frame-Options`) is the key defense against clickjacking of the OAuth
/// consent screen; it does not restrict resource loading, so it won't break the
/// dashboard's inline styles/scripts. HSTS is safe because the browser-facing
/// origin is always HTTPS (TLS terminated at the proxy).
async fn security_headers(mut res: Response) -> Response {
    const HEADERS: [(&str, &str); 5] = [
        ("x-frame-options", "DENY"),
        ("content-security-policy", "frame-ancestors 'none'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
    ];
    let h = res.headers_mut();
    for (name, value) in HEADERS {
        // Don't clobber a header a handler set deliberately.
        if !h.contains_key(name) {
            h.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
    }
    res
}

/// Resolve when the process receives SIGINT (Ctrl-C) or SIGTERM (`systemctl
/// restart`), so in-flight token/refresh requests drain instead of being killed.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
