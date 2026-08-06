//! Super-admin only: manage end users' fine-grained authorization (roles,
//! groups, and custom attributes). These are echoed into id/access tokens so
//! relying parties can enforce per-user access — a Keycloak-style subset.

use super::require_admin;
use crate::error::{AppError, AppResult};
use crate::models::{Admin, User};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use axum_extra::extract::cookie::SignedCookieJar;
use base64::Engine;
use minijinja::context;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Guard: resolve the caller and require the `super` role.
async fn require_super(state: &AppState, jar: &SignedCookieJar) -> AppResult<Admin> {
    let admin = require_admin(state, jar).await?;
    if !admin.can_manage_users() {
        return Err(AppError::Forbidden);
    }
    Ok(admin)
}

/// GET /dashboard/users — list all end users.
pub async fn list(State(state): State<AppState>, jar: SignedCookieJar) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let users = state.db.list_users().await?;
    let body = state.render(
        "users.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            users => users,
        },
    )?;
    Ok(Html(body))
}

/// Fetch a user or 404.
async fn user_in_scope(state: &AppState, id: &str) -> AppResult<User> {
    state.db.user_by_id(id).await?.ok_or(AppError::NotFound)
}

/// GET /dashboard/users/:id — edit a user's roles/groups/attributes.
pub async fn detail(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<Html<String>> {
    let admin = require_super(&state, &jar).await?;
    let user = user_in_scope(&state, &id).await?;

    // TOTP provisioning material (secret + QR), shown whenever enrolled so an
    // admin can re-scan or hand the setup key to the user.
    let (totp_secret, totp_uri, totp_qr) = match &user.totp_secret {
        Some(secret) if !secret.is_empty() => {
            let uri = crate::crypto::totp_provisioning_uri(
                &state.config.brand_title,
                &user.email,
                secret,
            );
            let qr = qrcode::QrCode::new(uri.clone())
                .ok()
                .map(|code| {
                    code.render::<qrcode::render::svg::Color>()
                        .min_dimensions(4, 4)
                        .build()
                })
                .map(|svg| {
                    format!(
                        "data:image/svg+xml;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(svg)
                    )
                });
            (secret.clone(), uri, qr)
        }
        _ => (String::new(), String::new(), None),
    };

    let body = state.render(
        "user_detail.html",
        context! {
            admin_email => admin.email,
            admin_role => admin.role,
            user => user,
            roles_text => user.roles.join("\n"),
            groups_text => user.groups.join("\n"),
            attributes_text => attributes_to_text(&user.attributes),
            totp_enabled => user.totp_enabled(),
            totp_secret => totp_secret,
            totp_uri => totp_uri,
            totp_qr => totp_qr,
        },
    )?;
    Ok(Html(body))
}

/// POST /dashboard/users/:id/totp/enable — generate + store a TOTP secret.
pub async fn enable_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let user = user_in_scope(&state, &id).await?;
    let secret = crate::crypto::generate_totp_secret();
    state.db.update_user_totp(&id, Some(&secret)).await?;
    tracing::info!(user = %user.email, "TOTP enrolled by admin");
    Ok(Redirect::to(&format!("/dashboard/users/{id}")))
}

/// POST /dashboard/users/:id/totp/disable — remove the TOTP secret.
pub async fn disable_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    let user = user_in_scope(&state, &id).await?;
    state.db.update_user_totp(&id, None).await?;
    tracing::warn!(user = %user.email, "TOTP disabled by admin");
    Ok(Redirect::to(&format!("/dashboard/users/{id}")))
}

#[derive(Deserialize)]
pub struct UserForm {
    roles: String,
    groups: String,
    attributes: String,
}

/// POST /dashboard/users/:id — save roles/groups/attributes (line-based).
pub async fn update(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Path(id): Path<String>,
    Form(form): Form<UserForm>,
) -> AppResult<impl IntoResponse> {
    require_super(&state, &jar).await?;
    user_in_scope(&state, &id).await?;

    let roles = parse_lines(&form.roles);
    let groups = parse_lines(&form.groups);
    let attrs = text_to_attributes(&form.attributes);

    // Reject a malformed attribute line explicitly rather than silently
    // dropping it (avoids surprising the admin).
    if attrs_is_invalid(&form.attributes) {
        return Err(AppError::bad(
            "attribute lines must be `key=value` (one per line)",
        ));
    }

    state.db.update_user(&id, &roles, &groups, &attrs).await?;
    Ok(Redirect::to(&format!("/dashboard/users/{id}")))
}

/// Split a textarea into trimmed, de-duplicated, non-empty lines.
fn parse_lines(input: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    input
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && seen.insert(l.clone()))
        .collect()
}

/// Detect a malformed attribute block: any non-empty line not of the form
/// `key=value` (with a non-empty key).
fn attrs_is_invalid(input: &str) -> bool {
    input.lines().any(|l| {
        let l = l.trim();
        !l.is_empty() && l.split_once('=').is_none_or(|(k, _)| k.trim().is_empty())
    })
}

/// Map → `key=value` lines for the textarea.
fn attributes_to_text(m: &BTreeMap<String, String>) -> String {
    m.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Textarea `key=value` lines → attribute map (validated by caller).
fn text_to_attributes(input: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in input.lines() {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                m.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_trims_dedups_and_skips_empty() {
        assert_eq!(
            parse_lines(" a \n a \n\n b \n"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(parse_lines("").is_empty());
    }

    #[test]
    fn attributes_roundtrip_via_text() {
        let m: BTreeMap<String, String> = [
            ("department".into(), "platform".into()),
            ("tier".into(), "gold".into()),
        ]
        .into_iter()
        .collect();
        let text = attributes_to_text(&m);
        assert!(!attrs_is_invalid(&text));
        assert_eq!(text_to_attributes(&text), m);
    }

    #[test]
    fn attributes_reject_bad_lines() {
        assert!(attrs_is_invalid("ok=1\nno-equals-here"));
        assert!(attrs_is_invalid("=missing-key"));
        assert!(!attrs_is_invalid("alright=1\nfine=2"));
        assert!(!attrs_is_invalid(""));
    }
}
