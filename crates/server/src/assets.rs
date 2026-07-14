//! Static branding assets, served from memory so the whole app is
//! self-contained — no CDN, no external fonts, nothing fetched at runtime.
//! This is what makes the UI work in airgapped deployments.
//!
//! The stylesheet is embedded at compile time. The logo and favicon default to
//! a bundled copy of the dalang.io logo, but each can be overridden with a local
//! file via `SSO_LOGO_PATH` / `SSO_FAVICON_PATH` (loaded once at startup).

use crate::config::Config;
use crate::state::AppState;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

const APP_CSS: &str = include_str!("../static/app.css");
/// Bundled fallback logo (downloaded from https://dalang.io/logo.webp).
const DEFAULT_LOGO: &[u8] = include_bytes!("../static/logo.webp");

/// An in-memory image asset (logo or favicon).
#[derive(Clone)]
pub struct BrandAsset {
    pub bytes: Arc<Vec<u8>>,
    pub content_type: String,
}

impl BrandAsset {
    /// Load from a file path, or fall back to the bundled default logo.
    pub fn load(path: Option<&str>) -> Self {
        if let Some(p) = path {
            match std::fs::read(p) {
                Ok(bytes) => {
                    return Self {
                        content_type: guess_mime(p).to_string(),
                        bytes: Arc::new(bytes),
                    };
                }
                Err(e) => {
                    tracing::warn!(path = %p, error = %e, "custom brand asset unreadable — using bundled default")
                }
            }
        }
        Self {
            bytes: Arc::new(DEFAULT_LOGO.to_vec()),
            content_type: "image/webp".to_string(),
        }
    }
}

/// The resolved branding for a running instance.
#[derive(Clone)]
pub struct Brand {
    pub title: String,
    pub logo: BrandAsset,
    pub favicon: BrandAsset,
}

impl Brand {
    pub fn from_config(config: &Config) -> Self {
        Self {
            title: config.brand_title.clone(),
            logo: BrandAsset::load(config.logo_path.as_deref()),
            favicon: BrandAsset::load(config.favicon_path.as_deref()),
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/assets/app.css", get(css))
        .route("/assets/logo", get(logo))
        .route("/assets/favicon", get(favicon))
}

async fn css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        APP_CSS,
    )
        .into_response()
}

async fn logo(State(state): State<AppState>) -> Response {
    image_response(&state.brand.logo)
}

async fn favicon(State(state): State<AppState>) -> Response {
    image_response(&state.brand.favicon)
}

fn image_response(asset: &BrandAsset) -> Response {
    (
        [
            (header::CONTENT_TYPE, asset.content_type.clone()),
            (header::CACHE_CONTROL, "public, max-age=86400".to_string()),
        ],
        asset.bytes.to_vec(),
    )
        .into_response()
}

fn guess_mime(path: &str) -> &'static str {
    match path
        .rsplit('.')
        .next()
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}
