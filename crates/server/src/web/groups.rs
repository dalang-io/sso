//! Super-admin only: manage the realm's group catalog. Groups are the
//! canonical, admin-managed list that end users "belong to" by name (see
//! `users.groups`), echoed into id/access tokens so relying parties can enforce
//! per-user access.

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
    if !admin.can_manage_users() {
        return Err(AppError::Forbidden);
    }
    Ok(admin)
}

/// GET /dashboard/groups — list the group catalog and each group's members.
pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let groups = state.db.list_groups().await?;
    let users = state.db.list_users().await?;
    let body = state.render(
        "groups.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            groups => groups,
            users => users,
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct NameForm {
    name: String,
}

#[derive(Deserialize)]
pub struct EmailForm {
    email: String,
}

/// POST /dashboard/groups — create a new group.
pub async fn create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<NameForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let name = form.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::bad("group name cannot be empty"));
    }
    if !state.db.create_group(&name).await? {
        return Err(AppError::bad("group already exists"));
    }
    tracing::info!("group created: {name}");
    Ok(Redirect::to("/dashboard/groups"))
}

/// POST /dashboard/groups/:name/delete — remove a group.
pub async fn delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    state.db.delete_group(&name).await?;
    tracing::info!("group deleted: {name}");
    Ok(Redirect::to("/dashboard/groups"))
}

/// POST /dashboard/groups/:name/assign — add a user to a group.
pub async fn assign(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<EmailForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let email = form.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::bad("email cannot be empty"));
    }
    state.db.assign_group_to_user(&email, &name).await?;
    tracing::info!(user = %email, group = %name, "assigned group to user");
    Ok(Redirect::to("/dashboard/groups"))
}

/// POST /dashboard/groups/:name/unassign — remove a user from a group.
pub async fn unassign(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(name): Path<String>,
    Form(form): Form<EmailForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let email = form.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::bad("email cannot be empty"));
    }
    state.db.remove_group_from_user(&email, &name).await?;
    tracing::info!(user = %email, group = %name, "removed group from user");
    Ok(Redirect::to("/dashboard/groups"))
}
