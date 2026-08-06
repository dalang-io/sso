//! End-user self-service: an authenticated user's account page where they can
//! self-enroll/disable TOTP two-factor auth and change their password — without
//! an administrator. Reached at `/account` while signed in as an end user.

use crate::crypto;
use crate::error::AppResult;
use crate::security;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use base64::Engine;
use minijinja::context;
use serde::Deserialize;

const MIN_PASSWORD_LEN: usize = 8;

/// Require a signed-in end user.
async fn require_user(state: &AppState, jar: &SignedCookieJar) -> AppResult<crate::models::User> {
    super::enduser::current_user(state, jar)
        .await
        .ok_or(crate::error::AppError::Unauthorized)
}

/// GET /account — the user's profile + security settings.
pub async fn page(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let user = require_user(&state, &jar).await?;
    render(&state, &user.email, user.totp_secret.as_deref(), None, None)
}

/// POST /account/totp — show a fresh TOTP setup (QR + code-verify step). The
/// secret is NOT persisted until the user proves they can read it.
pub async fn enable_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(_): Form<serde_json::Value>,
) -> AppResult<Html<String>> {
    let user = require_user(&state, &jar).await?;
    if user.totp_enabled() {
        return render(
            &state,
            &user.email,
            user.totp_secret.as_deref(),
            Some("Two-factor authentication is already enabled.".into()),
            None,
        );
    }
    let secret = crypto::generate_totp_secret();
    let (uri, qr) = totp_material(&state, &user.email, &secret);
    render_pending(&state, &user.email, &secret, uri, qr, None)
}

/// POST /account/totp/verify — activate a pending TOTP secret after a correct
/// code is provided.
pub async fn verify_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(f): Form<VerifyForm>,
) -> AppResult<Response> {
    let user = require_user(&state, &jar).await?;
    let account = format!("acct-verify:{}", user.email);
    if !security::auth_allowed(&state.rate_limiter, &headers, Some(&account)) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        )
            .into_response());
    }
    let (uri, qr) = totp_material(&state, &user.email, &f.secret);
    if !crypto::verify_totp(&f.secret, &f.code) {
        return render_pending(
            &state,
            &user.email,
            &f.secret,
            uri,
            qr,
            Some("Invalid verification code. Your authenticator was not activated.".into()),
        )
        .map(|h| h.into_response());
    }
    state.db.update_user_totp(&user.id, Some(&f.secret)).await?;
    state.rate_limiter.clear(&account);
    render(
        &state,
        &user.email,
        Some(&f.secret),
        None,
        Some("Two-factor authentication is now enabled.".into()),
    )
    .map(|h| h.into_response())
}

#[derive(Deserialize)]
pub struct VerifyForm {
    pub secret: String,
    pub code: String,
}

/// POST /account/totp/disable — disable 2FA, requiring the current code.
pub async fn disable_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(f): Form<DisableForm>,
) -> AppResult<Response> {
    let user = require_user(&state, &jar).await?;
    let account = format!("acct-verify:{}", user.email);
    if !security::auth_allowed(&state.rate_limiter, &headers, Some(&account)) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        )
            .into_response());
    }
    let Some(secret) = user.totp_secret.as_deref().filter(|s| !s.is_empty()) else {
        return render(
            &state,
            &user.email,
            None,
            Some("No authenticator configured.".into()),
            None,
        )
        .map(|h| h.into_response());
    };
    if !crypto::verify_totp(secret, &f.code) {
        return render(
            &state,
            &user.email,
            Some(secret),
            Some("Invalid verification code — 2FA was not disabled.".into()),
            None,
        )
        .map(|h| h.into_response());
    }
    state.db.update_user_totp(&user.id, None).await?;
    state.rate_limiter.clear(&account);
    render(
        &state,
        &user.email,
        None,
        None,
        Some("Two-factor authentication is disabled.".into()),
    )
    .map(|h| h.into_response())
}

#[derive(Deserialize)]
pub struct DisableForm {
    pub code: String,
}

/// POST /account/password — change password (requires current password).
pub async fn change_password(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(f): Form<PasswordForm>,
) -> AppResult<Response> {
    let user = require_user(&state, &jar).await?;
    let account = format!("acct-pw:{}", user.email);
    if !security::auth_allowed(&state.rate_limiter, &headers, Some(&account)) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later.",
        )
            .into_response());
    }
    let secret = user.totp_secret.as_deref().filter(|s| !s.is_empty());
    let (err, msg) = if !crypto::verify_secret(&f.current, &user.password_hash) {
        (Some("Current password is incorrect.".to_string()), None)
    } else if f.new_password.len() < MIN_PASSWORD_LEN {
        (
            Some("New password must be at least 8 characters.".to_string()),
            None,
        )
    } else if f.new_password != f.confirm {
        (Some("New passwords do not match.".to_string()), None)
    } else {
        state
            .db
            .update_user_password(&user.id, &f.new_password)
            .await?;
        state.rate_limiter.clear(&account);
        (None, Some("Password updated.".to_string()))
    };
    render(&state, &user.email, secret, err, msg).map(|h| h.into_response())
}

#[derive(Deserialize)]
pub struct PasswordForm {
    pub current: String,
    pub new_password: String,
    pub confirm: String,
}

/// Render the account page in the normal (idle) state — 2FA already configured
/// (or none), plus messages.
fn render(
    state: &AppState,
    email: &str,
    totp_secret: Option<&str>,
    error: Option<String>,
    msg: Option<String>,
) -> AppResult<Html<String>> {
    let (enabled, secret, uri, qr) = match totp_secret.filter(|s| !s.is_empty()) {
        Some(s) => {
            let (uri, qr) = totp_material(state, email, s);
            (true, s.to_string(), uri, qr)
        }
        None => (false, String::new(), String::new(), None),
    };
    Ok(Html(state.render(
        "account.html",
        context! {
            email => email,
            totp_enabled => enabled,
            totp_secret => secret,
            totp_uri => uri,
            totp_qr => qr,
            pending_secret => None::<String>,
            pending_qr => None::<String>,
            pending_uri => String::new(),
            error => error,
            msg => msg,
        },
    )?))
}

/// Render the account page with a pending TOTP setup (awaiting code verification).
#[allow(clippy::too_many_arguments)]
fn render_pending(
    state: &AppState,
    email: &str,
    secret: &str,
    uri: String,
    qr: Option<String>,
    error: Option<String>,
) -> AppResult<Html<String>> {
    let pending_qr = qr.clone();
    Ok(Html(state.render(
        "account.html",
        context! {
            email => email,
            totp_enabled => false,
            totp_secret => String::new(),
            totp_uri => String::new(),
            totp_qr => None::<String>,
            pending_secret => Some(secret.to_string()),
            pending_qr => pending_qr,
            pending_uri => uri,
            error => error,
            msg => None::<String>,
        },
    )?))
}

/// TOTP provisioning material for `email` with `secret`: (uri, qr).
fn totp_material(state: &AppState, email: &str, secret: &str) -> (String, Option<String>) {
    let uri = crypto::totp_provisioning_uri(&state.config.brand_title, email, secret);
    let qr = qrcode::QrCode::new(uri.clone())
        .ok()
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(4, 4)
                .build()
        })
        .map(|svg| {
            format!(
                "data:image/svg+xml;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(svg)
            )
        });
    (uri, qr)
}
