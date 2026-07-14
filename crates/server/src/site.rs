//! Public marketing landing page + developer docs, served at `/`.
//!
//! The landing + docs pages go through the template engine so their asset URLs
//! carry the `?v=<hash>` cache-buster (same as the dashboard) — otherwise a CDN
//! could serve a stale stylesheet against a new page. Everything is embedded at
//! compile time so the whole site ships in one binary and works airgapped.

use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use minijinja::context;

const LLMS: &str = include_str!("../../../site/llms.txt");
const ROBOTS: &str = include_str!("../../../site/robots.txt");
const SITEMAP: &str = include_str!("../../../site/sitemap.xml");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/docs", get(docs))
        .route("/llms.txt", get(|| async { text(LLMS) }))
        .route("/robots.txt", get(|| async { text(ROBOTS) }))
        .route("/sitemap.xml", get(|| async { xml(SITEMAP) }))
}

async fn index(State(state): State<AppState>) -> AppResult<Html<String>> {
    Ok(Html(state.render("site_index.html", context! {})?))
}

async fn docs(State(state): State<AppState>) -> AppResult<Html<String>> {
    Ok(Html(state.render("site_docs.html", context! {})?))
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
