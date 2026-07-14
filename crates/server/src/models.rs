//! Domain models. These mirror the database rows but are dialect-agnostic:
//! IDs are UUID strings, timestamps are RFC3339 TEXT, booleans are INTEGER 0/1.
//! Storing portable primitives is what lets one schema run on SQLite, Postgres,
//! and MySQL/MariaDB unchanged (see `db`).

use serde::Serialize;

/// An admin user of the dashboard (not an end-user of a downstream app).
#[derive(Clone, Debug, Serialize)]
pub struct Admin {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
}

/// An end user who authenticates to relying apps via this SSO. Distinct from
/// [`Admin`], who only manages the dashboard.
#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: String,
}

/// A registered OAuth 2.0 client — the equivalent of a "Google Cloud project
/// credential". Owns its authorized origins and redirect URIs.
#[derive(Clone, Debug, Serialize)]
pub struct Client {
    pub id: String,
    /// Public identifier handed to relying apps (`client_id`).
    pub client_id: String,
    /// Argon2 hash of the secret; the plaintext is shown exactly once at creation.
    #[serde(skip_serializing)]
    pub client_secret_hash: String,
    pub name: String,
    /// CORS allow-list for browser (implicit/PKCE) flows.
    pub js_origins: Vec<String>,
    /// Exact-match allow-list the `redirect_uri` parameter is validated against.
    pub redirect_uris: Vec<String>,
    pub created_at: String,
}

/// A short-lived authorization code (RFC 6749 §4.1), exchanged at `/oauth/token`.
#[derive(Clone, Debug)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub subject: String,
    /// PKCE challenge, if the client used it (RFC 7636).
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: String,
}

/// A persisted refresh token, exchangeable for new access tokens.
#[derive(Clone, Debug)]
pub struct RefreshToken {
    pub token_hash: String,
    pub client_id: String,
    pub subject: String,
    pub scope: String,
    pub expires_at: String,
}

/// Standard OIDC token endpoint response body.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}
