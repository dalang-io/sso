//! CRUD handlers for OAuth client registrations (the dashboard's core job).

use super::require_admin;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::{Client, MAX_CLIENT_SECRETS};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::Deserialize;

/// Generate a fresh secret: returns (plaintext shown once, display hint, hash).
fn generate_secret() -> (String, String, AppResult<String>) {
    let plaintext = crypto::random_token(32);
    let hint = format!("{}…", &plaintext[..plaintext.len().min(5)]);
    let hash = crypto::hash_secret(&plaintext).map_err(AppError::Other);
    (plaintext, hint, hash)
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
    let clients = state.db.list_clients().await?;
    let body = state.render(
        "clients.html",
        context! { admin_email => admin.email, admin_role => admin.role, clients => clients },
    )?;
    Ok(Html(body).into_response())
}

#[derive(Deserialize)]
pub struct CreateForm {
    name: String,
}

pub async fn create(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<CreateForm>,
) -> AppResult<Html<String>> {
    let admin = require_admin(&state, &jar).await?;

    let client = Client {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: crypto::random_token(16),
        name: form.name.trim().to_string(),
        js_origins: vec![],
        redirect_uris: vec![],
        allowed_emails: vec![],
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    state.db.create_client(&client).await?;

    // Issue the client's first secret; the plaintext is shown exactly once.
    let (secret, hint, hash) = generate_secret();
    state
        .db
        .add_client_secret(&client.id, &hint, &hash?)
        .await?;

    let body = state.render(
        "client_created.html",
        context! {
            admin_email => admin.email,
            id => client.id,
            client_id => client.client_id,
            client_secret => secret,
        },
    )?;
    Ok(Html(body))
}

/// POST /dashboard/clients/:id/secrets — add a secret (rotation), max 2.
pub async fn add_secret(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let admin = require_admin(&state, &jar).await?;
    let client = state
        .db
        .client_by_uuid(&id)
        .await?
        .ok_or(AppError::NotFound)?;

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
    require_admin(&state, &jar).await?;
    state
        .db
        .client_by_uuid(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state.db.delete_client_secret(&id, &sid).await?;
    Ok(Redirect::to(&format!("/dashboard/clients/{id}")).into_response())
}

pub async fn detail(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<Html<String>> {
    let admin = require_admin(&state, &jar).await?;
    let client = state
        .db
        .client_by_uuid(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let secrets = state.db.list_client_secrets(&id).await?;
    let can_add_secret = secrets.len() < MAX_CLIENT_SECRETS;
    let body = state.render(
        "client_detail.html",
        context! {
            admin_email => admin.email,
            client => client,
            secrets => secrets,
            can_add_secret => can_add_secret,
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
    require_admin(&state, &jar).await?;
    state
        .db
        .client_by_uuid(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    let js = parse_lines(&form.js_origins);
    let uris = parse_lines(&form.redirect_uris);
    let emails = parse_lines(&form.allowed_emails);
    state
        .db
        .update_client_config(&id, &js, &uris, &emails)
        .await?;
    Ok(Redirect::to(&format!("/dashboard/clients/{id}")))
}

pub async fn delete(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_admin(&state, &jar).await?;
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
