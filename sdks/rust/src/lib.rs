//! Rust client SDK for Dalang SSO.
//!
//! Drives the Authorization Code + PKCE flow against a self-hosted Dalang SSO
//! instance and exchanges codes for tokens. Mirrors the Google OAuth client
//! shape: you configure `client_id`, `client_secret`, and a `redirect_uri`.
//!
//! ```no_run
//! use dalang_sso::{Client, Pkce};
//! let sso = Client::new("https://sso.example.com", "CLIENT_ID", "CLIENT_SECRET", "https://app.example.com/callback");
//! let pkce = Pkce::generate();
//! let url = sso.authorize_url("openid email", "state123", Some(&pkce));
//! // ... redirect the user to `url`, receive `code` at your callback ...
//! # async fn run(sso: Client, pkce: Pkce) -> Result<(), dalang_sso::Error> {
//! let tokens = sso.exchange_code("CODE", Some(&pkce)).await?;
//! println!("access token: {}", tokens.access_token);
//! # Ok(()) }
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("oauth error: {code} — {description}")]
    OAuth { code: String, description: String },
}

/// A PKCE verifier/challenge pair (RFC 7636, S256).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn generate() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let verifier = URL_SAFE_NO_PAD.encode(buf);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: String,
}

pub struct Client {
    base_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Build the URL to redirect the user's browser to for consent.
    pub fn authorize_url(&self, scope: &str, state: &str, pkce: Option<&Pkce>) -> String {
        let mut url = url::Url::parse(&format!("{}/oauth/authorize", self.base_url)).unwrap();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", &self.client_id);
            q.append_pair("redirect_uri", &self.redirect_uri);
            q.append_pair("scope", scope);
            q.append_pair("state", state);
            if let Some(p) = pkce {
                q.append_pair("code_challenge", &p.challenge);
                q.append_pair("code_challenge_method", "S256");
            }
        }
        url.to_string()
    }

    /// Exchange an authorization code for tokens at the token endpoint.
    pub async fn exchange_code(&self, code: &str, pkce: Option<&Pkce>) -> Result<Tokens, Error> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
        ];
        if let Some(p) = pkce {
            form.push(("code_verifier", p.verifier.clone()));
        }
        self.post_token(&form).await
    }

    /// Exchange a refresh token for a fresh set of tokens.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, Error> {
        let form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
        ];
        self.post_token(&form).await
    }

    async fn post_token(&self, form: &[(&str, String)]) -> Result<Tokens, Error> {
        let resp = self
            .http
            .post(format!("{}/oauth/token", self.base_url))
            .form(form)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            #[derive(Deserialize)]
            struct Err_ {
                error: String,
                #[serde(default)]
                error_description: String,
            }
            let e: Err_ = resp.json().await?;
            Err(Error::OAuth {
                code: e.error,
                description: e.error_description,
            })
        }
    }
}
