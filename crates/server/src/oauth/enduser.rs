//! End-user accounts and session for the OAuth login screen.
//!
//! End users are the people signing in to relying apps — separate from dashboard
//! admins. Their session is a single signed cookie holding the user id (no
//! server-side session store, keeping the tier stateless). Handlers here run
//! *inside* the authorization flow: they authenticate the user, then hand back
//! to the consent screen carrying the original OAuth request via [`AuthzParams`].

use super::authorize::{render_consent, render_login, validate, AuthzParams};
use crate::error::AppResult;
use crate::models::User;
use crate::state::AppState;
use axum::extract::State;
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

fn session_cookie(user_id: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(USER_COOKIE, user_id);
    cookie.set_http_only(true);
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
}

/// POST /oauth/login — authenticate an existing end user, then show consent.
pub async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(f): Form<CredsForm>,
) -> AppResult<impl IntoResponse> {
    let client = validate(&state, &f.params).await?;

    let user = state.db.user_by_email(f.email.trim()).await?;
    match user {
        Some(u) if crate::crypto::verify_secret(&f.password, &u.password_hash) => {
            // Authenticated — now check this client's email allow-list.
            if !client.email_allowed(&u.email) {
                let msg = super::authorize::email_denied_msg(&u.email, &client);
                return Ok(render_login(&state, &client, &f.params, Some(&msg))?.into_response());
            }
            let jar = jar.add(session_cookie(u.id));
            Ok((jar, render_consent(&state, &client, &f.params, &u.email)?).into_response())
        }
        _ => Ok(render_login(
            &state,
            &client,
            &f.params,
            Some("Invalid email or password"),
        )?
        .into_response()),
    }
}

/// POST /oauth/register — create an end user, then show consent.
pub async fn register(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(f): Form<CredsForm>,
) -> AppResult<impl IntoResponse> {
    let client = validate(&state, &f.params).await?;
    let email = f.email.trim();

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
    let jar = jar.add(session_cookie(user.id));
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
