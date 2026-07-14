//! Super-admin only: manage tenants and members (dashboard users + their roles).

use super::require_admin;
use crate::error::{AppError, AppResult};
use crate::models::{Admin, ASSIGNABLE_ROLES};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Guard: resolve the caller and require the `super` role.
async fn require_super(state: &AppState, jar: &SignedCookieJar) -> AppResult<Admin> {
    let admin = require_admin(state, jar).await?;
    if !admin.is_super() {
        return Err(AppError::Forbidden);
    }
    Ok(admin)
}

// ---- tenants -------------------------------------------------------------

pub async fn tenants_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let tenants = state.db.list_tenants().await?;
    let clients = state.db.list_clients().await?;
    let members = state.db.list_admins().await?;
    // Per-tenant counts for the listing.
    let mut client_counts: BTreeMap<String, i64> = BTreeMap::new();
    for c in &clients {
        if let Some(t) = &c.tenant_id {
            *client_counts.entry(t.clone()).or_default() += 1;
        }
    }
    let mut member_counts: BTreeMap<String, i64> = BTreeMap::new();
    for m in &members {
        if let Some(t) = &m.tenant_id {
            *member_counts.entry(t.clone()).or_default() += 1;
        }
    }
    let body = state.render(
        "tenants.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            tenants => tenants,
            client_counts => client_counts,
            member_counts => member_counts,
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct TenantForm {
    name: String,
}

pub async fn create_tenant(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<TenantForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let name = form.name.trim();
    if name.is_empty() {
        return Err(AppError::bad("tenant name is required"));
    }
    state.db.create_tenant(name).await?;
    Ok(Redirect::to("/dashboard/tenants"))
}

pub async fn delete_tenant(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    // Refuse to delete a tenant that still owns clients or members.
    if !state.db.list_clients_for_tenant(&id).await?.is_empty() {
        return Err(AppError::bad(
            "tenant still has clients — delete them first",
        ));
    }
    if state
        .db
        .list_admins()
        .await?
        .iter()
        .any(|m| m.tenant_id.as_deref() == Some(&id))
    {
        return Err(AppError::bad(
            "tenant still has members — remove them first",
        ));
    }
    state.db.delete_tenant(&id).await?;
    Ok(Redirect::to("/dashboard/tenants"))
}

// ---- members -------------------------------------------------------------

pub async fn members_page(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let members = state.db.list_admins().await?;
    let tenants = state.db.list_tenants().await?;
    let tenant_names: BTreeMap<String, String> = tenants
        .iter()
        .map(|t| (t.id.clone(), t.name.clone()))
        .collect();
    let body = state.render(
        "members.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            self_id => admin.id,
            members => members,
            tenants => tenants,
            tenant_names => tenant_names,
            roles => ASSIGNABLE_ROLES,
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct MemberForm {
    email: String,
    password: String,
    role: String,
    #[serde(default)]
    tenant_id: String,
}

pub async fn create_member(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<MemberForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let email = form.email.trim();

    if !email.contains('@') {
        return Err(AppError::bad("enter a valid email address"));
    }
    if form.password.len() < 8 {
        return Err(AppError::bad("password must be at least 8 characters"));
    }
    if !ASSIGNABLE_ROLES.contains(&form.role.as_str()) {
        return Err(AppError::bad("role must be manager or developer"));
    }
    // Managers and developers must belong to a real tenant.
    state
        .db
        .tenant_by_id(&form.tenant_id)
        .await?
        .ok_or_else(|| AppError::bad("select a tenant"))?;
    if state.db.admin_by_email(email).await?.is_some() {
        return Err(AppError::bad("a member with that email already exists"));
    }

    state
        .db
        .create_admin(email, &form.password, &form.role, Some(&form.tenant_id))
        .await?;
    Ok(Redirect::to("/dashboard/members"))
}

pub async fn delete_member(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let admin = require_super(&state, &jar).await?;
    if admin.id == id {
        return Err(AppError::bad("you cannot delete your own account"));
    }
    state.db.delete_admin(&id).await?;
    Ok(Redirect::to("/dashboard/members"))
}
