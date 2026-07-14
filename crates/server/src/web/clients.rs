//! CRUD handlers for OAuth client registrations — tenant-scoped and role-gated.
//!
//! Access rules (see `models::Admin`):
//! - super:     every tenant; all client + secret operations.
//! - manager:   own tenant; create/delete clients, edit config, manage secrets.
//! - developer: own tenant; add/delete secrets only.

use super::require_admin;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::{Admin, Client, MAX_CLIENT_SECRETS};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Generate a fresh secret: returns (plaintext shown once, display hint, hash).
fn generate_secret() -> (String, String, AppResult<String>) {
    let plaintext = crypto::random_token(32);
    let hint = format!("{}…", &plaintext[..plaintext.len().min(5)]);
    let hash = crypto::hash_secret(&plaintext).map_err(AppError::Other);
    (plaintext, hint, hash)
}

/// Fetch a client and enforce that `admin` may act on its tenant (else 404).
async fn client_in_scope(state: &AppState, admin: &Admin, id: &str) -> AppResult<Client> {
    let client = state
        .db
        .client_by_uuid(id)
        .await?
        .ok_or(AppError::NotFound)?;
    if !admin.can_access_tenant(client.tenant_id.as_deref()) {
        return Err(AppError::NotFound);
    }
    Ok(client)
}

pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Response> {
    // Unauthenticated visitors go to onboarding (no admin yet) or login.
    let admin = match super::current_admin(&state, &jar).await {
        Some(a) => a,
        None => {
            let to = if state.db.count_admins().await? == 0 {
                "/setup"
            } else {
                "/login"
            };
            return Ok(Redirect::to(to).into_response());
        }
    };

    // Super sees every client; others only their tenant's.
    let clients = if admin.is_super() {
        state.db.list_clients().await?
    } else if let Some(t) = &admin.tenant_id {
        state.db.list_clients_for_tenant(t).await?
    } else {
        vec![]
    };

    // Map tenant id -> name for display (super view shows the owning tenant).
    let tenants = state.db.list_tenants().await?;
    let tenant_names: BTreeMap<String, String> = tenants
        .iter()
        .map(|t| (t.id.clone(), t.name.clone()))
        .collect();

    let body = state.render(
        "clients.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            clients => clients,
            tenant_names => tenant_names,
            tenants => tenants,
            can_create => admin.can_manage_clients(),
            is_super => admin.is_super(),
        },
    )?;
    Ok(Html(body).into_response())
}

#[derive(Deserialize)]
pub struct CreateForm {
    name: String,
    #[serde(default)]
    tenant_id: String,
}

pub async fn create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CreateForm>,
) -> AppResult<Html<String>> {
    let admin = require_admin(&state, &jar).await?;
    if !admin.can_manage_clients() {
        return Err(AppError::Forbidden);
    }

    // The owning tenant: super picks it from the form; managers use their own.
    let tenant_id = if admin.is_super() {
        if form.tenant_id.is_empty() {
            return Err(AppError::bad("select a tenant for this client"));
        }
        form.tenant_id.clone()
    } else {
        admin
            .tenant_id
            .clone()
            .ok_or_else(|| AppError::bad("you are not assigned to a tenant"))?
    };
    // Validate the tenant exists.
    state
        .db
        .tenant_by_id(&tenant_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let client = Client {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: crypto::random_token(16),
        tenant_id: Some(tenant_id),
        name: form.name.trim().to_string(),
        js_origins: vec![],
        redirect_uris: vec![],
        allowed_emails: vec![],
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    state.db.create_client(&client).await?;

    let (secret, hint, hash) = generate_secret();
    state
        .db
        .add_client_secret(&client.id, &hint, &hash?)
        .await?;

    let body = state.render(
        "client_created.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            id => client.id,
            client_id => client.client_id,
            client_secret => secret,
        },
    )?;
    Ok(Html(body))
}

pub async fn detail(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<Html<String>> {
    let admin = require_admin(&state, &jar).await?;
    let client = client_in_scope(&state, &admin, &id).await?;
    let secrets = state.db.list_client_secrets(&id).await?;
    let can_add_secret = secrets.len() < MAX_CLIENT_SECRETS;
    let body = state.render(
        "client_detail.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            client => client,
            secrets => secrets,
            can_add_secret => can_add_secret,
            can_manage => admin.can_manage_clients(),
            js_origins_text => client.js_origins.join("\n"),
            redirect_uris_text => client.redirect_uris.join("\n"),
            allowed_emails_text => client.allowed_emails.join("\n"),
            no_email_filter => client.allowed_emails.is_empty(),
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct UrisForm {
    js_origins: String,
    redirect_uris: String,
    allowed_emails: String,
}

pub async fn update_uris(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<UrisForm>,
) -> AppResult<impl IntoResponse> {
    let admin = require_admin(&state, &jar).await?;
    client_in_scope(&state, &admin, &id).await?;
    if !admin.can_manage_clients() {
        return Err(AppError::Forbidden);
    }
    let js = parse_lines(&form.js_origins);
    let uris = parse_lines(&form.redirect_uris);
    let emails = parse_lines(&form.allowed_emails);
    state
        .db
        .update_client_config(&id, &js, &uris, &emails)
        .await?;
    Ok(Redirect::to(&format!("/dashboard/clients/{id}")))
}

/// POST /dashboard/clients/:id/secrets — add a secret (rotation), max 2.
/// Allowed for developers too.
pub async fn add_secret(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let admin = require_admin(&state, &jar).await?;
    let client = client_in_scope(&state, &admin, &id).await?;
    if !admin.can_manage_secrets() {
        return Err(AppError::Forbidden);
    }

    let secrets = state.db.list_client_secrets(&id).await?;
    if secrets.len() >= MAX_CLIENT_SECRETS {
        return Err(AppError::bad(format!(
            "a client may have at most {MAX_CLIENT_SECRETS} secrets — delete one before adding another"
        )));
    }

    let (secret, hint, hash) = generate_secret();
    state.db.add_client_secret(&id, &hint, &hash?).await?;

    let body = state.render(
        "secret_created.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            id => client.id,
            client_name => client.name,
            client_secret => secret,
        },
    )?;
    Ok(Html(body).into_response())
}

/// POST /dashboard/clients/:id/secrets/:sid/delete — remove one secret.
pub async fn delete_secret(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path((id, sid)): Path<(String, String)>,
) -> AppResult<Response> {
    let admin = require_admin(&state, &jar).await?;
    client_in_scope(&state, &admin, &id).await?;
    if !admin.can_manage_secrets() {
        return Err(AppError::Forbidden);
    }
    state.db.delete_client_secret(&id, &sid).await?;
    Ok(Redirect::to(&format!("/dashboard/clients/{id}")).into_response())
}

pub async fn delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let admin = require_admin(&state, &jar).await?;
    client_in_scope(&state, &admin, &id).await?;
    if !admin.can_manage_clients() {
        return Err(AppError::Forbidden);
    }
    state.db.delete_client(&id).await?;
    Ok(Redirect::to("/dashboard"))
}

/// Split a textarea into a trimmed, de-duplicated, non-empty list of entries.
fn parse_lines(input: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    input
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && seen.insert(l.clone()))
        .collect()
}
