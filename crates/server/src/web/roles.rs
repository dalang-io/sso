//! Super-admin only: manage the realm's role catalog. A role is a named
//! capability that end users "hold" (their `users.roles` JSON); this page is the
//! canonical, admin-managed list of known roles, plus which users hold each one.

use super::require_admin;
use crate::error::{AppError, AppResult};
use crate::models::Admin;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::Deserialize;

/// Guard: resolve the caller and require the `super` role.
async fn require_super(state: &AppState, jar: &SignedCookieJar) -> AppResult<Admin> {
    let admin = require_admin(state, jar).await?;
    if !admin.is_super() {
        return Err(AppError::Forbidden);
    }
    Ok(admin)
}

/// GET /dashboard/roles — list the role catalog and who holds each role.
pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let roles = state.db.list_roles().await?;
    let users = state.db.list_users().await?;
    let body = state.render(
        "roles.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            roles => roles,
            users => users,
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct NameForm {
    name: String,
}

/// POST /dashboard/roles — create a new role.
pub async fn create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<NameForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let name = form.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("role name cannot be empty"));
    }
    if !state.db.create_role(name).await? {
        return Err(AppError::bad("role already exists"));
    }
    Ok(Redirect::to("/dashboard/roles"))
}

/// POST /dashboard/roles/:name/delete — remove a role from the catalog.
pub async fn delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    state.db.delete_role(&name).await?;
    Ok(Redirect::to("/dashboard/roles"))
}

#[derive(Deserialize)]
pub struct EmailForm {
    email: String,
}

/// POST /dashboard/roles/:name/assign — grant the role to a user by email.
pub async fn assign(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<EmailForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    state.db.assign_role_to_user(&form.email, &name).await?;
    Ok(Redirect::to("/dashboard/roles"))
}

/// POST /dashboard/roles/:name/unassign — revoke the role from a user.
pub async fn unassign(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<EmailForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    state.db.remove_role_from_user(&form.email, &name).await?;
    Ok(Redirect::to("/dashboard/roles"))
}
