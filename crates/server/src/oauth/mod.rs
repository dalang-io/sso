//! OAuth 2.0 / OpenID Connect provider endpoints.
//!
//! Implements the Authorization Code flow (with PKCE), refresh-token and
//! client-credentials grants, plus OIDC discovery, JWKS and UserInfo. Access
//! and id tokens are stateless RS256 JWTs; only refresh tokens hit the DB.

pub mod authorize;
pub mod token;
pub mod userinfo;

use crate::crypto::Keys;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route(
            "/oauth/authorize",
            get(authorize::show).post(authorize::decide),
        )
        .route("/oauth/token", post(token::exchange))
        .route("/oauth/userinfo", get(userinfo::userinfo))
}

/// JWT claim set for access and id tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Sign a claim set as an RS256 JWT with the active `kid` (classical backend).
pub fn mint_rsa_jwt(keys: &Keys, claims: &Claims) -> anyhow::Result<String> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(keys.kid.clone());
    Ok(jsonwebtoken::encode(&header, claims, &keys.encoding)?)
}

/// Verify an RS256 JWT signature and standard claims, returning its payload.
pub fn verify_rsa_jwt(keys: &Keys, token: &str, issuer: &str) -> anyhow::Result<Claims> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Claims>(token, &keys.decoding, &validation)?;
    Ok(data.claims)
}

async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.signer.jwks())
}

/// OIDC discovery document (RFC 8414 / OpenID Connect Discovery 1.0).
async fn discovery(State(state): State<AppState>) -> Json<serde_json::Value> {
    let iss = state.config.issuer();
    Json(serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "userinfo_endpoint": format!("{iss}/oauth/userinfo"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [state.signer.alg()],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["openid", "email", "profile"],
    }))
}
