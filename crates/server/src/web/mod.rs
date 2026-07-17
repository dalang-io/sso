//! Dashboard: admin session auth + the client-management UI (htmx over server
//! rendered templates). Session state is a single signed cookie holding the
//! admin's id — no server-side session store, which keeps horizontal scaling
//! trivial (any node can serve any request).

pub mod admin;
pub mod clients;

use crate::error::{AppError, AppResult};
use crate::models::Admin;
use crate::state::AppState;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use minijinja::context;
use serde::Deserialize;

const SESSION_COOKIE: &str = "sso_admin";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/setup", get(setup_page).post(setup))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/dashboard", get(clients::list))
        .route("/dashboard/clients", post(clients::create))
        .route("/dashboard/clients/:id", get(clients::detail))
        .route("/dashboard/clients/:id/uris", post(clients::update_uris))
        .route("/dashboard/clients/:id/secrets", post(clients::add_secret))
        .route(
            "/dashboard/clients/:id/secrets/:sid/delete",
            post(clients::delete_secret),
        )
        .route("/dashboard/clients/:id/delete", post(clients::delete))
        // super-admin: tenants + members
        .route(
            "/dashboard/tenants",
            get(admin::tenants_page).post(admin::create_tenant),
        )
        .route("/dashboard/tenants/:id/delete", post(admin::delete_tenant))
        .route(
            "/dashboard/members",
            get(admin::members_page).post(admin::create_member),
        )
        .route("/dashboard/members/:id/delete", post(admin::delete_member))
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

/// Build the signed admin-session cookie for `admin_id`. `secure` gates the
/// `Secure` attribute (config `SSO_COOKIE_SECURE`, default true).
fn admin_session_cookie(admin_id: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, admin_id);
    cookie.set_http_only(true);
    cookie.set_secure(secure);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie
}

// ---- first-run onboarding ------------------------------------------------

#[derive(Deserialize)]
struct SetupForm {
    email: String,
    password: String,
    password_confirm: String,
}

/// GET /setup — one-time page to create the first (super) admin. Once any admin
/// exists it is disabled and redirects to the login page.
async fn setup_page(State(state): State<AppState>) -> AppResult<Response> {
    if state.db.count_admins().await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }
    Ok(Html(state.render("setup.html", context! {})?).into_response())
}

/// POST /setup — create the super admin, sign them in, go to the dashboard.
async fn setup(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<SetupForm>,
) -> AppResult<Response> {
    // Guard against a race / repeat submission: onboarding runs exactly once.
    if state.db.count_admins().await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }

    let email = form.email.trim();
    let error = if !email.contains('@') {
        Some("Enter a valid email address")
    } else if form.password.len() < 8 {
        Some("Password must be at least 8 characters")
    } else if form.password != form.password_confirm {
        Some("Passwords do not match")
    } else {
        None
    };
    if let Some(msg) = error {
        return Ok(Html(state.render("setup.html", context! { error => msg })?).into_response());
    }

    // Super admin is global (no tenant). Seed a default tenant so clients have
    // somewhere to live out of the box.
    let admin = state
        .db
        .create_admin(email, &form.password, "super", None)
        .await?;
    state.db.ensure_default_tenant().await?;
    tracing::info!(email = %admin.email, "super admin created via onboarding");
    Ok((
        jar.add(admin_session_cookie(admin.id, state.config.cookie_secure)),
        Redirect::to("/dashboard"),
    )
        .into_response())
}

// ---- admin login ---------------------------------------------------------

async fn login_page(State(state): State<AppState>) -> AppResult<Response> {
    // No admin yet → send the operator through onboarding instead.
    if state.db.count_admins().await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    Ok(Html(state.render("login.html", context! {})?).into_response())
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
    if state.db.count_admins().await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    let admin = state.db.admin_by_email(&form.email).await?;
    match admin {
        Some(a) if crate::crypto::verify_secret(&form.password, &a.password_hash) => Ok((
            jar.add(admin_session_cookie(a.id, state.config.cookie_secure)),
            Redirect::to("/dashboard"),
        )
            .into_response()),
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
