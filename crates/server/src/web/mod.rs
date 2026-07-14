//! Dashboard: admin session auth + the client-management UI (htmx over server
//! rendered templates). Session state is a single signed cookie holding the
//! admin's id — no server-side session store, which keeps horizontal scaling
//! trivial (any node can serve any request).

pub mod clients;

use crate::error::{AppError, AppResult};
use crate::models::Admin;
use crate::state::AppState;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use minijinja::context;
use serde::Deserialize;

const SESSION_COOKIE: &str = "sso_admin";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/dashboard", get(clients::list))
        .route("/dashboard/clients", post(clients::create))
        .route("/dashboard/clients/:id", get(clients::detail))
        .route("/dashboard/clients/:id/uris", post(clients::update_uris))
        .route("/dashboard/clients/:id/delete", post(clients::delete))
}

/// Resolve the signed-in admin from the session cookie, or `None`.
pub async fn current_admin(state: &AppState, jar: &SignedCookieJar) -> Option<Admin> {
    let id = jar.get(SESSION_COOKIE)?.value().to_string();
    state.db.admin_by_id(&id).await.ok().flatten()
}

/// Guard for dashboard handlers: returns the admin or a 401.
pub async fn require_admin(state: &AppState, jar: &SignedCookieJar) -> AppResult<Admin> {
    current_admin(state, jar)
        .await
        .ok_or(AppError::Unauthorized)
}

async fn login_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    Ok(Html(state.render("login.html", context! {})?))
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> AppResult<impl IntoResponse> {
    let admin = state.db.admin_by_email(&form.email).await?;
    match admin {
        Some(a) if crate::crypto::verify_secret(&form.password, &a.password_hash) => {
            let mut cookie = Cookie::new(SESSION_COOKIE, a.id);
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);
            cookie.set_path("/");
            Ok((jar.add(cookie), Redirect::to("/dashboard")).into_response())
        }
        _ => {
            let body = state.render(
                "login.html",
                context! { error => "Invalid email or password" },
            )?;
            Ok(Html(body).into_response())
        }
    }
}

async fn logout(jar: SignedCookieJar) -> impl IntoResponse {
    (
        jar.remove(Cookie::from(SESSION_COOKIE)),
        Redirect::to("/login"),
    )
}
