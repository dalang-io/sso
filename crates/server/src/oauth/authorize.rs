//! Authorization endpoint (RFC 6749 §4.1 + PKCE §7636).
//!
//! GET validates the request, then either shows the **end-user login** screen
//! (if nobody is signed in) or the **consent** screen (if they are). The issued
//! authorization code is bound to the authenticated user from the session
//! cookie — never to a value the browser can choose. Account handling lives in
//! [`super::enduser`].

use super::enduser::current_user;
use crate::error::{AppError, AppResult};
use crate::models::{AuthCode, Client};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The OAuth request parameters, carried unchanged through login → consent so
/// the flow can resume after authentication.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthzParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
}

impl AuthzParams {
    fn scope_or_default(&self) -> String {
        if self.scope.is_empty() {
            "openid".to_string()
        } else {
            self.scope.clone()
        }
    }

    /// Flatten to a map for re-emitting as hidden form fields in templates.
    fn to_map(&self) -> BTreeMap<&'static str, String> {
        let mut m = BTreeMap::new();
        m.insert("response_type", self.response_type.clone());
        m.insert("client_id", self.client_id.clone());
        m.insert("redirect_uri", self.redirect_uri.clone());
        m.insert("scope", self.scope.clone());
        m.insert("state", self.state.clone());
        if let Some(c) = &self.code_challenge {
            m.insert("code_challenge", c.clone());
        }
        if let Some(mth) = &self.code_challenge_method {
            m.insert("code_challenge_method", mth.clone());
        }
        m
    }
}

/// Validate `response_type`, the client, and the redirect URI (shared by every
/// entry point into the flow).
pub(super) async fn validate(state: &AppState, p: &AuthzParams) -> AppResult<Client> {
    if p.response_type != "code" {
        return Err(AppError::oauth(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    let client = state
        .db
        .client_by_client_id(&p.client_id)
        .await?
        .ok_or_else(|| AppError::oauth("invalid_client", "unknown client_id"))?;
    if !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return Err(AppError::oauth(
            "invalid_request",
            "redirect_uri not authorized for this client",
        ));
    }
    Ok(client)
}

/// Render the end-user login/registration screen, preserving the OAuth request.
pub(super) fn render_login(
    state: &AppState,
    client: &Client,
    p: &AuthzParams,
    error: Option<&str>,
) -> AppResult<Html<String>> {
    let body = state.render(
        "oauth_login.html",
        context! {
            client_name => client.name,
            params => p.to_map(),
            error => error,
        },
    )?;
    Ok(Html(body))
}

/// Render the consent screen for an already-authenticated user.
pub(super) fn render_consent(
    state: &AppState,
    client: &Client,
    p: &AuthzParams,
    user_email: &str,
) -> AppResult<Html<String>> {
    let body = state.render(
        "consent.html",
        context! {
            client_name => client.name,
            scope => p.scope_or_default(),
            user_email => user_email,
            params => p.to_map(),
        },
    )?;
    Ok(Html(body))
}

/// GET /oauth/authorize — login screen if signed out, consent screen if in.
pub async fn show(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(p): Query<AuthzParams>,
) -> AppResult<Html<String>> {
    let client = validate(&state, &p).await?;
    match current_user(&state, &jar).await {
        Some(user) => render_consent(&state, &client, &p, &user.email),
        None => render_login(&state, &client, &p, None),
    }
}

/// Consent decision form: the OAuth params (flattened) plus the button pressed.
#[derive(Debug, Deserialize)]
pub struct DecideForm {
    #[serde(flatten)]
    pub params: AuthzParams,
    pub decision: String,
}

/// POST /oauth/authorize — record the consent decision for the signed-in user.
pub async fn decide(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(f): Form<DecideForm>,
) -> AppResult<impl IntoResponse> {
    let client = validate(&state, &f.params).await?;

    // The subject comes from the authenticated session, not the request body.
    let user = current_user(&state, &jar)
        .await
        .ok_or_else(|| AppError::oauth("access_denied", "not signed in"))?;

    if f.decision != "allow" {
        return Ok(Redirect::to(&append_query(
            &f.params.redirect_uri,
            &[("error", "access_denied"), ("state", &f.params.state)],
        )));
    }

    let code = crate::crypto::random_token(32);
    let expires =
        chrono::Utc::now() + chrono::Duration::from_std(state.config.auth_code_ttl).unwrap();
    state
        .db
        .insert_auth_code(&AuthCode {
            code: code.clone(),
            client_id: client.client_id,
            redirect_uri: f.params.redirect_uri.clone(),
            scope: f.params.scope_or_default(),
            subject: user.email,
            code_challenge: f.params.code_challenge,
            code_challenge_method: f.params.code_challenge_method,
            expires_at: expires.to_rfc3339(),
        })
        .await?;

    Ok(Redirect::to(&append_query(
        &f.params.redirect_uri,
        &[("code", &code), ("state", &f.params.state)],
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
