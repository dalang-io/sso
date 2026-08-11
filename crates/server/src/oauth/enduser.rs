//! End-user accounts and session for the OAuth login screen.
//!
//! End users are the people signing in to relying apps — separate from dashboard
//! admins. Their session is a single signed cookie holding the user id (no
//! server-side session store, keeping the tier stateless). Handlers here run
//! *inside* the authorization flow: they authenticate the user, then hand back
//! to the consent screen carrying the original OAuth request via [`AuthzParams`].

use super::authorize::{
    render_consent, render_force_pw_login, render_login, render_mfa_login, validate, AuthzParams,
    MfaStep,
};
use crate::error::AppResult;
use crate::models::User;
use crate::security;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::Deserialize;

const USER_COOKIE: &str = "sso_end_user";
const MIN_PASSWORD_LEN: usize = 8;

/// Resolve the signed-in end user from the session cookie, if any.
pub async fn current_user(state: &AppState, jar: &SignedCookieJar) -> Option<User> {
    let id = jar.get(USER_COOKIE)?.value().to_string();
    state.db.user_by_id(&id).await.ok().flatten()
}

fn session_cookie(user_id: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(USER_COOKIE, user_id);
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie
}

/// Credentials submitted from the login/register forms, alongside the OAuth
/// request parameters (flattened) so the flow can continue to consent.
#[derive(Debug, Deserialize)]
pub struct CredsForm {
    #[serde(flatten)]
    pub params: AuthzParams,
    pub email: String,
    pub password: String,
    /// Present on the two-factor step: the TOTP code.
    #[serde(default)]
    pub mfa_code: String,
    /// Present on the forced-password-change step.
    #[serde(default)]
    pub fpw_new: String,
    #[serde(default)]
    pub fpw_confirm: String,
}

/// POST /oauth/login — authenticate an existing end user, then show consent.
pub async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(f): Form<CredsForm>,
) -> AppResult<impl IntoResponse> {
    let client = validate(&state, &f.params).await?;

    // Brute-force guard: budget per client IP and per account.
    if !security::auth_allowed(&state.rate_limiter, &headers, Some(f.email.trim())) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Please try again later.",
        )
            .into_response());
    }

    let Some(user) = state.db.user_by_email(f.email.trim()).await? else {
        return Ok(render_login(
            &state,
            &client,
            &f.params,
            Some("Invalid email or password"),
        )?
        .into_response());
    };
    if !crate::crypto::verify_secret(&f.password, &user.password_hash) {
        return Ok(render_login(
            &state,
            &client,
            &f.params,
            Some("Invalid email or password"),
        )?
        .into_response());
    }

    // Password OK. Two-factor policy:
    //   1. Client requires MFA but the user has none -> deny.
    //   2. User has TOTP enrolled -> require a valid code before a session.
    if client.require_mfa && !user.totp_enabled() {
        return Ok(render_login(
            &state,
            &client,
            &f.params,
            Some(
                "This app requires two-factor authentication, but your account \
                 doesn't have it configured. Contact an administrator.",
            ),
        )?
        .into_response());
    }
    if user.totp_enabled() {
        let code = f.mfa_code.trim();
        let valid = !code.is_empty()
            && crate::crypto::verify_totp(user.totp_secret.as_deref().unwrap_or_default(), code);
        if !valid {
            let err = if code.is_empty() {
                None
            } else {
                Some("Invalid verification code — try again.".to_string())
            };
            return Ok(render_mfa_login(
                &state,
                &client,
                &f.params,
                MfaStep {
                    email: user.email.clone(),
                    password: f.password.clone(),
                    error: err,
                },
            )?
            .into_response());
        }
    }

    // Fully authenticated (password + MFA satisfied) — reset the lockout budget.
    state.rate_limiter.clear(&format!("acct:{}", user.email));

    // Required action: force password change on next login.
    if user.force_pw_change {
        let err = if f.fpw_new.is_empty() {
            None
        } else if f.fpw_new.len() < MIN_PASSWORD_LEN {
            Some("New password must be at least 8 characters.".into())
        } else if f.fpw_new != f.fpw_confirm {
            Some("New passwords do not match.".into())
        } else {
            state.db.update_user_password(&user.id, &f.fpw_new).await?;
            state.db.set_force_pw_change(&user.id, false).await?;
            None
        };
        if let Some(e) = err {
            return Ok(render_force_pw_login(
                &state,
                &client,
                &f.params,
                user.email.clone(),
                f.password.clone(),
                Some(e),
            )?
            .into_response());
        }
        // Password updated successfully — fall through to normal completion.
    }

    // Now check this client's email allow-list.
    if !client.email_allowed(&user.email) {
        let msg = super::authorize::email_denied_msg(&user.email, &client);
        return Ok(render_login(&state, &client, &f.params, Some(&msg))?.into_response());
    }
    let jar = jar.add(session_cookie(user.id, state.config.cookie_secure));
    Ok((
        jar,
        render_consent(&state, &client, &f.params, &user.email)?,
    )
        .into_response())
}

/// POST /oauth/register — create an end user, then show consent.
pub async fn register(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    headers: HeaderMap,
    Form(f): Form<CredsForm>,
) -> AppResult<impl IntoResponse> {
    let client = validate(&state, &f.params).await?;
    let email = f.email.trim();

    // Mass-account-creation guard (per IP, and per destination email).
    if !security::auth_allowed(&state.rate_limiter, &headers, Some(email)) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Please try again later.",
        )
            .into_response());
    }

    // New accounts can't satisfy a mandatory-2FA client until an admin enrolls
    // them, so refuse to create one that would be locked out.
    if client.require_mfa {
        return Ok(render_login(
            &state,
            &client,
            &f.params,
            Some(
                "This app requires two-factor authentication. Ask an administrator \
                 to create your account and set up 2FA.",
            ),
        )?
        .into_response());
    }

    let err: Option<String> = if !email.contains('@') {
        Some("Enter a valid email address".into())
    } else if f.password.len() < MIN_PASSWORD_LEN {
        Some("Password must be at least 8 characters".into())
    } else if !client.email_allowed(email) {
        // Don't create accounts that can't use the client they're registering for.
        Some(super::authorize::email_denied_msg(email, &client))
    } else if state.db.user_by_email(email).await?.is_some() {
        Some("An account with that email already exists".into())
    } else {
        None
    };
    if let Some(msg) = err {
        return Ok(render_login(&state, &client, &f.params, Some(&msg))?.into_response());
    }

    let user = state.db.create_user(email, &f.password).await?;
    state
        .db
        .write_audit(&user.email, "register", "", Some(&client.client_id))
        .await?;
    let jar = jar.add(session_cookie(user.id, state.config.cookie_secure));
    Ok((
        jar,
        render_consent(&state, &client, &f.params, &user.email)?,
    )
        .into_response())
}

/// GET /oauth/logout — clear the end-user session.
pub async fn logout(jar: SignedCookieJar) -> impl IntoResponse {
    (jar.remove(Cookie::from(USER_COOKIE)), Redirect::to("/"))
}
