//! Token introspection endpoint (RFC 7662) — `/oauth/introspect`.
//!
//! A client authenticates (client_secret_post/basic) and asks about a token it
//! has seen. Access/id tokens are self-verifying JWTs, so introspection never
//! touches the DB and can additionally reveal the RPT `authorization` grants.
//! Refresh tokens are looked up by hash (they're server-side anyway).

use super::token::authenticate_client;
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> AppResult<Json<Value>> {
    // The endpoint is protected like `/oauth/token`: the caller must be an
    // authenticated confidential client.
    authenticate_client(
        &state,
        &headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )
    .await?;

    let hint = form.token_type_hint.to_lowercase();

    // Access/id token path: self-verifying JWT, no DB.
    if hint.is_empty() || hint == "access_token" {
        if let Ok(claims) = state.signer.verify(&form.token, &state.config.issuer()) {
            return Ok(Json(access_introspection(&claims)));
        }
        // No hint and the JWT failed — maybe it's a refresh token; fall through.
        if !hint.is_empty() {
            return Ok(Json(json!({ "active": false })));
        }
    }

    // Refresh-token path: server-side lookup by hash.
    if hint.is_empty() || hint == "refresh_token" {
        if let Ok(Some(rt)) = state
            .db
            .refresh_token(&crate::crypto::sha256_hex(&form.token))
            .await
        {
            let expired = match chrono::DateTime::parse_from_rfc3339(&rt.expires_at) {
                Ok(t) => t < chrono::Utc::now(),
                Err(_) => true,
            };
            let active = !rt.revoked && !expired;
            let mut body = json!({ "active": active });
            if active {
                let exp = chrono::DateTime::parse_from_rfc3339(&rt.expires_at)
                    .map(|t| t.timestamp())
                    .unwrap_or(0);
                body["client_id"] = json!(rt.client_id);
                body["sub"] = json!(rt.subject);
                body["scope"] = json!(rt.scope);
                body["exp"] = json!(exp);
            }
            return Ok(Json(body));
        }
    }

    Ok(Json(json!({ "active": false })))
}

/// Build an RFC 7662 introspection response for a verified access/id token,
/// carrying the fine-grained claims (roles/groups/attributes) and any RPT
/// `authorization` grant embedded in the token.
fn access_introspection(c: &super::Claims) -> Value {
    let mut m: Map<String, Value> = Map::new();
    m.insert("active".into(), json!(true));
    m.insert("scope".into(), json!(c.scope));
    m.insert("client_id".into(), json!(c.aud));
    m.insert("sub".into(), json!(c.sub));
    m.insert("aud".into(), json!(c.aud));
    m.insert("iss".into(), json!(c.iss));
    m.insert("exp".into(), json!(c.exp));
    m.insert("iat".into(), json!(c.iat));
    if let Some(email) = &c.email {
        m.insert("email".into(), json!(email));
    }
    if !c.roles.is_empty() {
        m.insert("roles".into(), json!(c.roles));
    }
    if !c.groups.is_empty() {
        m.insert("groups".into(), json!(c.groups));
    }
    if !c.attributes.is_empty() {
        m.insert("attributes".into(), json!(c.attributes));
    }
    if let Some(authz) = &c.authorization {
        m.insert("authorization".into(), authz.clone());
    }
    Value::Object(m)
}
