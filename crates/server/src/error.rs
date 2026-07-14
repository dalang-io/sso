//! Unified error type. Converts into HTTP responses so handlers can `?` freely.
//!
//! OAuth endpoints return RFC 6749 §5.2 JSON error bodies; dashboard endpoints
//! render a plain message. Internal errors are logged and surfaced as 500s.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    /// An RFC 6749 OAuth error: (`error` code, human description).
    #[error("oauth error: {0}")]
    OAuth(&'static str, String),

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    pub fn bad(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }
    pub fn oauth(code: &'static str, desc: impl Into<String>) -> Self {
        AppError::OAuth(code, desc.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            AppError::OAuth(code, desc) => {
                let status = match *code {
                    "invalid_client" | "access_denied" => StatusCode::UNAUTHORIZED,
                    "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
                    _ => StatusCode::BAD_REQUEST,
                };
                let body = Json(json!({ "error": code, "error_description": desc }));
                return (status, body).into_response();
            }
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
            AppError::Other(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
