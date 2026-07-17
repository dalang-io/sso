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
    /// Whether session cookies carry the `Secure` attribute (browser only sends
    /// them over HTTPS). Defaults to true; the browser-facing origin is HTTPS even
    /// when the app terminates plain HTTP behind a TLS-terminating proxy. Set
    /// `SSO_COOKIE_SECURE=false` only for local plain-HTTP development.
    pub cookie_secure: bool,
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
            cookie_secure: env_or("SSO_COOKIE_SECURE", "true") != "false",
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

    /// Whether the server binds only to a loopback interface (local dev).
    /// Unparseable or wildcard/public binds are treated as non-loopback so the
    /// secure-default checks fail closed rather than open.
    fn is_loopback_bind(&self) -> bool {
        self.bind_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false)
    }

    /// Refuse to start with a shipped/placeholder session secret when exposed
    /// beyond loopback. The cookie signing key is `SHA-512(session_secret)`, so a
    /// world-known secret means forgeable admin/end-user sessions. Localhost dev
    /// keeps working with the default (only a warning). Call once at boot.
    pub fn validate(&self) -> anyhow::Result<()> {
        let weak = self.session_secret.starts_with("dev-insecure")
            || self.session_secret.contains("CHANGE_ME");
        if weak {
            if !self.is_loopback_bind() {
                anyhow::bail!(
                    "SSO_SESSION_SECRET is unset or a placeholder while binding to a \
                     non-loopback address ({}). The cookie signing key would be publicly \
                     derivable. Set a strong secret (`openssl rand -hex 32`) and restart. \
                     Refusing to start.",
                    self.bind_addr
                );
            }
            tracing::warn!(
                "SSO_SESSION_SECRET is a dev default — acceptable on localhost, NEVER in production"
            );
        } else if self.session_secret.len() < 32 {
            tracing::warn!(
                "SSO_SESSION_SECRET is shorter than 32 bytes — prefer `openssl rand -hex 32`"
            );
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(bind: &str, secret: &str) -> Config {
        Config {
            bind_addr: bind.into(),
            public_url: "http://localhost".into(),
            database_url: "sqlite::memory:".into(),
            database_max_connections: 1,
            session_secret: secret.into(),
            cookie_secure: true,
            jwt_private_key_path: None,
            token_signing_alg: "rs256".into(),
            access_token_ttl: Duration::from_secs(60),
            refresh_token_ttl: Duration::from_secs(60),
            auth_code_ttl: Duration::from_secs(60),
            brand_title: "x".into(),
            logo_path: None,
            favicon_path: None,
        }
    }

    const DEFAULT: &str = "dev-insecure-session-secret-change-me-0000";
    const STRONG: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn rejects_placeholder_secret_when_exposed() {
        // Wildcard/public binds must fail closed with a shipped/placeholder secret.
        assert!(cfg("0.0.0.0:80", DEFAULT).validate().is_err());
        assert!(cfg("[::]:80", DEFAULT).validate().is_err());
        assert!(cfg("1.2.3.4:80", "CHANGE_ME_openssl_rand_hex_32")
            .validate()
            .is_err());
    }

    #[test]
    fn allows_placeholder_secret_on_loopback() {
        // Zero-setup `cargo run` on localhost keeps working (warn only).
        assert!(cfg("127.0.0.1:8080", DEFAULT).validate().is_ok());
        assert!(cfg("[::1]:8080", DEFAULT).validate().is_ok());
    }

    #[test]
    fn allows_strong_secret_when_exposed() {
        assert!(cfg("0.0.0.0:80", STRONG).validate().is_ok());
    }
}
