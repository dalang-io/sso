//! Public marketing landing page + developer docs, served at `/`.
//!
//! Embedded at compile time (like the dashboard assets) so the whole site ships
//! inside the one binary and works airgapped. SEO/GEO support files (llms.txt,
//! robots.txt, sitemap.xml) are served here too.

use crate::state::AppState;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;

const INDEX: &str = include_str!("../../../site/index.html");
const DOCS: &str = include_str!("../../../site/docs.html");
const LLMS: &str = include_str!("../../../site/llms.txt");
const ROBOTS: &str = include_str!("../../../site/robots.txt");
const SITEMAP: &str = include_str!("../../../site/sitemap.xml");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/docs", get(|| async { Html(DOCS) }))
        .route("/llms.txt", get(|| async { text(LLMS) }))
        .route("/robots.txt", get(|| async { text(ROBOTS) }))
        .route("/sitemap.xml", get(|| async { xml(SITEMAP) }))
}

fn text(body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

fn xml(body: &'static str) -> Response {
    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    )
        .into_response()
}
