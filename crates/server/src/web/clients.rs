//! CRUD handlers for OAuth client registrations (the dashboard's core job).

use super::require_admin;
use crate::crypto;
use crate::error::{AppError, AppResult};
use crate::models::Client;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use minijinja::context;
use serde::Deserialize;

pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_admin(&state, &jar).await?;
    let clients = state.db.list_clients().await?;
    let body = state.render(
        "clients.html",
        context! { admin_email => admin.email, clients => clients },
    )?;
    Ok(Html(body))
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

    // `client_id` is public; the secret is shown once and only its hash persists.
    let secret = crypto::random_token(32);
    let client = Client {
        id: uuid::Uuid::new_v4().to_string(),
        client_id: crypto::random_token(16),
        client_secret_hash: crypto::hash_secret(&secret)?,
        name: form.name.trim().to_string(),
        js_origins: vec![],
        redirect_uris: vec![],
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    state.db.create_client(&client).await?;

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
    let body = state.render(
        "client_detail.html",
        context! {
            admin_email => admin.email,
            client => client,
            js_origins_text => client.js_origins.join("\n"),
            redirect_uris_text => client.redirect_uris.join("\n"),
        },
    )?;
    Ok(Html(body))
}

#[derive(Deserialize)]
pub struct UrisForm {
    js_origins: String,
    redirect_uris: String,
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
    state.db.update_client_uris(&id, &js, &uris).await?;
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
