//! Runtime configuration, loaded once at boot from the environment (`.env`).
//!
//! Every knob has a sane default so `cargo run` works with zero setup, falling
//! back to an embedded SQLite database and an ephemeral signing key.

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub public_url: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub session_secret: String,
    pub jwt_private_key_path: Option<String>,
    /// Token signing algorithm: `rs256` (default, max interop) or `ml-dsa-65`
    /// (post-quantum, FIPS 204).
    pub token_signing_alg: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub auth_code_ttl: Duration,
    /// Branding shown in the UI. All assets are served locally (airgap-safe).
    pub brand_title: String,
    /// Optional path to a custom logo/icon file; falls back to the bundled logo.
    pub logo_path: Option<String>,
    /// Optional path to a custom favicon file; falls back to the bundled logo.
    pub favicon_path: Option<String>,
}

impl Config {
    /// Read configuration from process environment. Missing values fall back to
    /// development-friendly defaults; secrets warn loudly when left at defaults.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind_addr: env_or("SSO_BIND_ADDR", "127.0.0.1:8080"),
            public_url: env_or("SSO_PUBLIC_URL", "http://localhost:8080"),
            database_url: env_or("DATABASE_URL", "sqlite://data/sso.db?mode=rwc"),
            database_max_connections: env_or("DATABASE_MAX_CONNECTIONS", "32").parse()?,
            session_secret: env_or(
                "SSO_SESSION_SECRET",
                "dev-insecure-session-secret-change-me-0000",
            ),
            jwt_private_key_path: std::env::var("SSO_JWT_PRIVATE_KEY_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            token_signing_alg: env_or("SSO_TOKEN_SIGNING_ALG", "rs256").to_lowercase(),
            access_token_ttl: secs("SSO_ACCESS_TOKEN_TTL", 3600),
            refresh_token_ttl: secs("SSO_REFRESH_TOKEN_TTL", 2_592_000),
            auth_code_ttl: secs("SSO_AUTH_CODE_TTL", 600),
            brand_title: env_or("SSO_BRAND_TITLE", "Dalang SSO"),
            logo_path: std::env::var("SSO_LOGO_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            favicon_path: std::env::var("SSO_FAVICON_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }

    /// The OpenID Connect `issuer` identifier — the public URL without a trailing slash.
    pub fn issuer(&self) -> String {
        self.public_url.trim_end_matches('/').to_string()
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn secs(key: &str, default: u64) -> Duration {
    let n = std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    Duration::from_secs(n)
}
