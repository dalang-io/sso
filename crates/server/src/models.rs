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
    /// `super` for the onboarding-created first admin, otherwise `admin`.
    pub role: String,
}

impl Admin {
    pub fn is_super(&self) -> bool {
        self.role == "super"
    }
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
    pub name: String,
    /// CORS allow-list for browser (implicit/PKCE) flows.
    pub js_origins: Vec<String>,
    /// Exact-match allow-list the `redirect_uri` parameter is validated against.
    pub redirect_uris: Vec<String>,
    /// Which end-user emails may sign in to this client. Patterns:
    /// `@domain` / `*@domain` (any address at that domain) or `user@domain`
    /// (one exact address). **Empty means allow all** (see the dashboard warning).
    pub allowed_emails: Vec<String>,
    pub created_at: String,
}

impl Client {
    /// Whether `email` is permitted to authenticate to this client.
    /// An empty allow-list permits everyone (open registration).
    pub fn email_allowed(&self, email: &str) -> bool {
        email_allowed(email, &self.allowed_emails)
    }
}

/// The maximum number of live secrets a client may hold at once.
pub const MAX_CLIENT_SECRETS: usize = 2;

/// One of a client's secrets. The plaintext is shown exactly once at creation;
/// only the Argon2 hash is stored, plus a short non-sensitive `hint` and the
/// creation timestamp so admins can tell secrets apart and rotate confidently.
#[derive(Clone, Debug, Serialize)]
pub struct ClientSecret {
    pub id: String,
    /// The owning client's UUID (`clients.id`).
    pub client_id: String,
    /// First few characters of the secret, for display (e.g. `k3Jd…`).
    pub hint: String,
    #[serde(skip_serializing)]
    pub secret_hash: String,
    pub created_at: String,
}

/// Match an email against a list of patterns (`@domain`, `*@domain`, or an exact
/// `user@domain`). An empty list allows everyone. Case-insensitive.
pub fn email_allowed(email: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let e = email.trim().to_lowercase();
    let domain = e.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
    patterns.iter().any(|p| {
        let p = p.trim().to_lowercase();
        match p.strip_prefix("*@").or_else(|| p.strip_prefix('@')) {
            Some(d) => !d.is_empty() && domain == d, // domain pattern
            None => e == p,                          // exact address
        }
    })
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

#[cfg(test)]
mod tests {
    use super::email_allowed;

    fn pats(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_allows_everyone() {
        assert!(email_allowed("anyone@anywhere.com", &[]));
    }

    #[test]
    fn domain_patterns_match_domain_only() {
        let p = pats(&["@dalang.io", "*@intern.dalang.io"]);
        assert!(email_allowed("han@dalang.io", &p));
        assert!(email_allowed("BOB@Intern.Dalang.IO", &p)); // case-insensitive
        assert!(!email_allowed("han@evil.io", &p));
        assert!(!email_allowed("han@sub.dalang.io", &p)); // not a subdomain match
    }

    #[test]
    fn exact_address_matches_only_itself() {
        let p = pats(&["user@example.com"]);
        assert!(email_allowed("user@example.com", &p));
        assert!(!email_allowed("other@example.com", &p));
    }

    #[test]
    fn mixed_list() {
        let p = pats(&["@dalang.io", "vip@example.com"]);
        assert!(email_allowed("x@dalang.io", &p));
        assert!(email_allowed("vip@example.com", &p));
        assert!(!email_allowed("nope@example.com", &p));
    }
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
