//! Token endpoint (RFC 6749 §3.2). Supports the `authorization_code`,
//! `refresh_token` and `client_credentials` grants. Client authentication is
//! accepted via `client_secret_post` (form) or `client_secret_basic` (header).

use super::Claims;
use crate::error::{AppError, AppResult};
use crate::models::{Client, RefreshToken, TokenResponse};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Form, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scope: String,
}

pub async fn exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> AppResult<Json<TokenResponse>> {
    let (client_id, client_secret) = client_credentials(&headers, &form)
        .ok_or_else(|| AppError::oauth("invalid_client", "missing client credentials"))?;

    let client = state
        .db
        .client_by_client_id(&client_id)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_client", "unknown client"))?;

    // A client may hold up to two secrets (for rotation); accept any live one.
    let secrets = state.db.list_client_secrets(&client.id).await?;
    let ok = secrets
        .iter()
        .any(|s| crate::crypto::verify_secret(&client_secret, &s.secret_hash));
    if !ok {
        return Err(AppError::oauth("invalid_client", "bad client secret"));
    }

    match form.grant_type.as_str() {
        "authorization_code" => auth_code_grant(&state, &client, &form).await,
        "refresh_token" => refresh_grant(&state, &client, &form).await,
        "client_credentials" => Ok(Json(
            // Machine-to-machine: no end user, so never an id_token/nonce and a
            // fresh (unused) refresh family is irrelevant since with_refresh=false.
            issue(
                &state,
                &client,
                &client.client_id,
                &form.scope,
                false,
                None,
                None,
            )
            .await?,
        )),
        other => Err(AppError::oauth(
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        )),
    }
}

async fn auth_code_grant(
    state: &AppState,
    client: &Client,
    form: &TokenForm,
) -> AppResult<Json<TokenResponse>> {
    let code = form
        .code
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing code"))?;
    let stored = state
        .db
        .take_auth_code(code)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_grant", "unknown or used code"))?;

    if stored.client_id != client.client_id {
        return Err(AppError::oauth(
            "invalid_grant",
            "code was issued to another client",
        ));
    }
    if expired(&stored.expires_at) {
        return Err(AppError::oauth(
            "invalid_grant",
            "authorization code expired",
        ));
    }
    if let Some(uri) = &form.redirect_uri {
        if uri != &stored.redirect_uri {
            return Err(AppError::oauth("invalid_grant", "redirect_uri mismatch"));
        }
    }

    // PKCE: if the code was issued with a challenge, a matching verifier is required.
    if let Some(challenge) = &stored.code_challenge {
        let method = stored.code_challenge_method.as_deref().unwrap_or("plain");
        let verifier = form
            .code_verifier
            .as_deref()
            .ok_or_else(|| AppError::oauth("invalid_grant", "code_verifier required"))?;
        if !crate::crypto::verify_pkce(verifier, challenge, method) {
            return Err(AppError::oauth("invalid_grant", "PKCE verification failed"));
        }
    }

    // A brand-new consent starts a fresh rotation family (None → issue() mints one).
    Ok(Json(
        issue(
            state,
            client,
            &stored.subject,
            &stored.scope,
            true,
            stored.nonce.as_deref(),
            None,
        )
        .await?,
    ))
}

async fn refresh_grant(
    state: &AppState,
    client: &Client,
    form: &TokenForm,
) -> AppResult<Json<TokenResponse>> {
    let presented = form
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::oauth("invalid_request", "missing refresh_token"))?;
    let hash = crate::crypto::sha256_hex(presented);
    let stored = state
        .db
        .refresh_token(&hash)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_grant", "unknown refresh token"))?;

    // Reuse detection: presenting an already-rotated (tombstoned) token means the
    // token was leaked and replayed. Revoke the entire rotation family — the
    // legitimate holder will re-authenticate — and refuse.
    if stored.revoked {
        state.db.revoke_refresh_family(&stored.family_id).await?;
        tracing::warn!(
            client_id = %client.client_id,
            family = %stored.family_id,
            "refresh token reuse detected — revoked family"
        );
        return Err(AppError::oauth(
            "invalid_grant",
            "refresh token reuse detected",
        ));
    }
    if stored.client_id != client.client_id || expired(&stored.expires_at) {
        return Err(AppError::oauth(
            "invalid_grant",
            "refresh token invalid or expired",
        ));
    }

    // Rotate atomically: only the request that flips revoked 0→1 wins. A lost
    // race means a concurrent rotation/replay — treat it as reuse and revoke.
    if !state.db.consume_refresh_token(&hash).await? {
        state.db.revoke_refresh_family(&stored.family_id).await?;
        return Err(AppError::oauth(
            "invalid_grant",
            "refresh token reuse detected",
        ));
    }

    // New token stays in the same family so the chain remains linkable.
    Ok(Json(
        issue(
            state,
            client,
            &stored.subject,
            &stored.scope,
            true,
            None,
            Some(&stored.family_id),
        )
        .await?,
    ))
}

/// Mint an access token (+ optional id_token and rotating refresh token).
/// `nonce` (if any) is echoed into the id_token; `refresh_family` continues an
/// existing rotation lineage, or `None` starts a new one.
async fn issue(
    state: &AppState,
    client: &Client,
    subject: &str,
    scope: &str,
    with_refresh: bool,
    nonce: Option<&str>,
    refresh_family: Option<&str>,
) -> AppResult<TokenResponse> {
    let now = chrono::Utc::now().timestamp();
    let ttl = state.config.access_token_ttl.as_secs() as i64;
    let iss = state.config.issuer();

    let access = state
        .signer
        .sign(&Claims {
            iss: iss.clone(),
            sub: subject.to_string(),
            aud: client.client_id.clone(),
            exp: now + ttl,
            iat: now,
            scope: scope.to_string(),
            email: None,
            nonce: None,
        })
        .map_err(AppError::Other)?;

    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        Some(
            state
                .signer
                .sign(&Claims {
                    iss,
                    sub: subject.to_string(),
                    aud: client.client_id.clone(),
                    exp: now + ttl,
                    iat: now,
                    scope: String::new(),
                    email: Some(subject.to_string()),
                    nonce: nonce.map(str::to_string),
                })
                .map_err(AppError::Other)?,
        )
    } else {
        None
    };

    let refresh_token = if with_refresh {
        let raw = crate::crypto::random_token(32);
        let expires = chrono::Utc::now()
            + chrono::Duration::from_std(state.config.refresh_token_ttl).unwrap();
        let rt = RefreshToken {
            token_hash: crate::crypto::sha256_hex(&raw),
            client_id: client.client_id.clone(),
            subject: subject.to_string(),
            scope: scope.to_string(),
            // Continue the presented token's family, or start a new lineage.
            family_id: refresh_family
                .map(str::to_string)
                .unwrap_or_else(|| crate::crypto::random_token(16)),
            revoked: false,
            expires_at: expires.to_rfc3339(),
        };
        // Persist before returning so the token is usable immediately.
        state.db.insert_refresh_token(&rt).await?;
        Some(raw)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ttl,
        refresh_token,
        id_token,
        scope: scope.to_string(),
    })
}

/// Resolve client credentials from the form (`client_secret_post`) or from a
/// `client_secret_basic` Authorization header.
fn client_credentials(headers: &HeaderMap, form: &TokenForm) -> Option<(String, String)> {
    if let (Some(id), Some(secret)) = (&form.client_id, &form.client_secret) {
        return Some((id.clone(), secret.clone()));
    }
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let b64 = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(b64).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn expired(rfc3339: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(rfc3339) {
        Ok(t) => t < chrono::Utc::now(),
        Err(_) => true,
    }
}
