//! Shared application state, cloned cheaply into every request handler.

use crate::assets::Brand;
use crate::config::Config;
use crate::db::Db;
use crate::signing::Signer;
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use minijinja::Environment;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub signer: Arc<Signer>,
    pub brand: Brand,
    pub templates: Arc<Environment<'static>>,
    pub cookie_key: Key,
}

impl AppState {
    pub fn new(config: Config, db: Db, signer: Signer) -> Self {
        // The cookie signer needs exactly >= 64 bytes; SHA-512 expands a secret
        // of any length deterministically. (`Key::from` panics on < 64.)
        use sha2::{Digest, Sha512};
        let expanded = Sha512::digest(config.session_secret.as_bytes());
        let cookie_key = Key::from(&expanded);

        let brand = Brand::from_config(&config);
        // Branding is available to every template without per-handler plumbing.
        let mut env = build_templates();
        env.add_global("brand_title", brand.title.clone());
        env.add_global("favicon_mime", brand.favicon.content_type.clone());

        Self {
            config: Arc::new(config),
            db,
            signer: Arc::new(signer),
            brand,
            templates: Arc::new(env),
            cookie_key,
        }
    }

    /// Render a template to an HTML string, mapping errors to 500s.
    pub fn render(&self, name: &str, ctx: minijinja::Value) -> crate::error::AppResult<String> {
        let tmpl = self
            .templates
            .get_template(name)
            .map_err(|e| crate::error::AppError::Other(anyhow::anyhow!("template {name}: {e}")))?;
        tmpl.render(ctx)
            .map_err(|e| crate::error::AppError::Other(anyhow::anyhow!("render {name}: {e}")))
    }
}

// Lets axum-extra's SignedCookieJar pull the signing key straight from state.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

/// Templates are embedded at compile time so the binary is self-contained and
/// there is no runtime filesystem dependency (important for container deploys).
fn build_templates() -> Environment<'static> {
    let mut env = Environment::new();
    env.add_template("base.html", include_str!("../templates/base.html"))
        .unwrap();
    env.add_template("login.html", include_str!("../templates/login.html"))
        .unwrap();
    env.add_template("setup.html", include_str!("../templates/setup.html"))
        .unwrap();
    env.add_template(
        "clients.html",
        include_str!("../templates/dashboard/clients.html"),
    )
    .unwrap();
    env.add_template(
        "client_detail.html",
        include_str!("../templates/dashboard/client_detail.html"),
    )
    .unwrap();
    env.add_template(
        "secret_created.html",
        include_str!("../templates/dashboard/secret_created.html"),
    )
    .unwrap();
    env.add_template(
        "client_created.html",
        include_str!("../templates/dashboard/client_created.html"),
    )
    .unwrap();
    env.add_template(
        "consent.html",
        include_str!("../templates/oauth/consent.html"),
    )
    .unwrap();
    env.add_template(
        "oauth_login.html",
        include_str!("../templates/oauth/login.html"),
    )
    .unwrap();
    env
}
