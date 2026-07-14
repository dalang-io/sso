//! Authorization endpoint (RFC 6749 §4.1 + PKCE §7636).
//!
//! GET renders a consent screen; POST records the user's decision and, on
//! approval, issues a single-use authorization code redirected back to the app.

use crate::error::{AppError, AppResult};
use crate::models::AuthCode;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use minijinja::context;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

pub async fn show(
    State(state): State<AppState>,
    Query(q): Query<AuthQuery>,
) -> AppResult<Html<String>> {
    if q.response_type != "code" {
        return Err(AppError::oauth(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    let client = state
        .db
        .client_by_client_id(&q.client_id)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_client", "unknown client_id"))?;

    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return Err(AppError::oauth(
            "invalid_request",
            "redirect_uri not authorized for this client",
        ));
    }

    // Re-echo the request parameters as hidden fields through the consent form.
    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("response_type", q.response_type.clone());
    params.insert("client_id", q.client_id.clone());
    params.insert("redirect_uri", q.redirect_uri.clone());
    params.insert("scope", q.scope.clone());
    params.insert("state", q.state.clone());
    if let Some(c) = &q.code_challenge {
        params.insert("code_challenge", c.clone());
    }
    if let Some(m) = &q.code_challenge_method {
        params.insert("code_challenge_method", m.clone());
    }

    let scope = if q.scope.is_empty() {
        "openid".to_string()
    } else {
        q.scope.clone()
    };
    let body = state.render(
        "consent.html",
        context! { client_name => client.name, scope => scope, params => params },
    )?;
    Ok(Html(body))
}

#[derive(Debug, Deserialize)]
pub struct DecideForm {
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    pub subject: String,
    pub decision: String,
}

pub async fn decide(
    State(state): State<AppState>,
    Form(f): Form<DecideForm>,
) -> AppResult<impl IntoResponse> {
    let client = state
        .db
        .client_by_client_id(&f.client_id)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_client", "unknown client_id"))?;
    if !client.redirect_uris.iter().any(|u| u == &f.redirect_uri) {
        return Err(AppError::oauth(
            "invalid_request",
            "redirect_uri not authorized",
        ));
    }

    if f.decision != "allow" {
        return Ok(Redirect::to(&append_query(
            &f.redirect_uri,
            &[("error", "access_denied"), ("state", &f.state)],
        )));
    }

    let code = crate::crypto::random_token(32);
    let expires =
        chrono::Utc::now() + chrono::Duration::from_std(state.config.auth_code_ttl).unwrap();
    state
        .db
        .insert_auth_code(&AuthCode {
            code: code.clone(),
            client_id: f.client_id,
            redirect_uri: f.redirect_uri.clone(),
            scope: if f.scope.is_empty() {
                "openid".into()
            } else {
                f.scope
            },
            subject: f.subject,
            code_challenge: f.code_challenge,
            code_challenge_method: f.code_challenge_method,
            expires_at: expires.to_rfc3339(),
        })
        .await?;

    Ok(Redirect::to(&append_query(
        &f.redirect_uri,
        &[("code", &code), ("state", &f.state)],
    )))
}

/// Append query parameters to a redirect URI, respecting an existing `?`.
fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let pairs: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect();
    if pairs.is_empty() {
        return base.to_string();
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{}", pairs.join("&"))
}

fn urlencode(s: &str) -> String {
    serde_urlencoded::to_string([("_", s)])
        .ok()
        .and_then(|q| q.strip_prefix("_=").map(str::to_string))
        .unwrap_or_else(|| s.to_string())
}
