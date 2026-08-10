//! Super-admin only: the audit log of every auth-relevant event (login,
//! register, consent, token issuance). Read-only view of `Db::list_audit`.

use super::require_admin;
use crate::error::{AppError, AppResult};
use crate::models::Admin;
use crate::state::AppState;
use axum::extract::State;
use axum::response::Html;
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

/// GET /dashboard/audit — list the most recent audit events.
pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let events = state.db.list_audit(200).await?;
    let body = state.render(
        "audit.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            events => events,
        },
    )?;
    Ok(Html(body))
}
