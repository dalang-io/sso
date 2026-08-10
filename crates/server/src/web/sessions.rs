//! Super-admin only: list and revoke end-user sign-in sessions.

use super::require_admin;
use crate::error::{AppError, AppResult};
use crate::models::Admin;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;

/// Guard: resolve the caller and require the `super` role.
async fn require_super(state: &AppState, jar: &SignedCookieJar) -> AppResult<Admin> {
    let admin = require_admin(state, jar).await?;
    if !admin.is_super() {
        return Err(AppError::Forbidden);
    }
    Ok(admin)
}

/// GET /dashboard/sessions — list all active end-user sign-in sessions.
pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let sessions = state.db.list_sessions().await?;
    let body = state.render(
        "sessions.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            sessions => sessions,
        },
    )?;
    Ok(Html(body))
}

/// POST /dashboard/sessions/:id/revoke — delete an end-user sign-in session.
pub async fn revoke(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    state.db.delete_session(&id).await?;
    Ok(Redirect::to("/dashboard/sessions"))
}
