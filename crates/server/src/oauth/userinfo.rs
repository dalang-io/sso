//! UserInfo endpoint (OIDC). Returns claims for the subject bound to a valid
//! Bearer access token.

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::json;

pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<serde_json::Value>> {
    let token = bearer(&headers).ok_or(AppError::Unauthorized)?;
    let claims = state
        .signer
        .verify(&token, &state.config.issuer())
        .map_err(|_| AppError::oauth("invalid_token", "access token invalid or expired"))?;

    let mut body = json!({
        "sub": claims.sub,
        "email": claims.email.unwrap_or(claims.sub),
    });
    // Echo fine-grained authorization embedded in the access token, so relying
    // parties can enforce per-user access without this endpoint hitting the DB.
    if !claims.roles.is_empty() {
        body["roles"] = json!(claims.roles);
    }
    if !claims.groups.is_empty() {
        body["groups"] = json!(claims.groups);
    }
    if !claims.attributes.is_empty() {
        body["attributes"] = json!(claims.attributes);
    }
    Ok(Json(body))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}
