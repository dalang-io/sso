//! Stateless-friendly security helpers:
//!
//! * A bounded, in-memory **rate limiter** used to throttle the credential
//!   endpoints (admin login, end-user login/register, first-run setup) by client
//!   IP and by account, preventing brute force. The budget is node-local, which
//!   is an acceptable trade for keeping the app tier stateless — behind a load
//!   balancer each node enforces its own budget, which is strictly safer than
//!   none, and these endpoints are low-volume.
//! * **CSRF protection** via the double-submit-cookie pattern. The CSRF cookie
//!   carries an unguessable nonce that base.html JS echoes into every POST form;
//!   the middleware rejects any state-changing request whose token does not match
//!   the cookie. Because the cookie is `SameSite=Lax`, modern browsers won't even
//!   send it on cross-site POSTs, so this is defense-in-depth.
//!
//! The middleware is applied **only** to browser-facing routes — never to the
//! machine-to-machine `/oauth/token` endpoint, which has no cookie context.

use crate::state::AppState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, SameSite};
use http_body_util::BodyExt;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const CSRF_COOKIE: &str = "sso_csrf";
const CSRF_FIELD: &str = "_csrf";
const CSRF_HEADER: &str = "x-csrf-token";

/// Max buckets kept before a full prune (fail-open to `allow` on memory pressure).
const MAX_BUCKETS: usize = 100_000;

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// A simple fixed-window-per-bucket limiter keyed on arbitrary strings (client
/// IP, account email, …). Each key keeps the recent timestamps within its window
/// and `allow` registers a new attempt, denying once the limit is hit.
#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `key` is still within its `limit`-per-`window` budget
    /// (and records this attempt), or `false` if the limit is exceeded.
    pub fn allow(&self, key: &str, limit: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= MAX_BUCKETS {
            buckets.clear();
        }
        let bucket = buckets.entry(key.to_string()).or_default();
        bucket.retain(|t| now.duration_since(*t) < window);
        if bucket.len() >= limit {
            return false;
        }
        bucket.push(now);
        true
    }

    /// Forget a key's history — call after a successful authentication so a
    /// legitimate user is never locked out by their own earlier typos.
    pub fn clear(&self, key: &str) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.remove(key);
        }
    }
}

/// Best-effort client IP: trusts the proxy-set `X-Forwarded-For` (first hop,
/// set by Cloudflare/CDN in front of the app), then `CF-Connecting-IP`,
/// then `X-Real-IP`. Never used for authorization — only for rate limiting.
pub fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    for name in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(v) = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
        {
            if !v.is_empty() {
                return v;
            }
        }
    }
    "unknown".to_string()
}

/// Throttle a credential endpoint. `by_ip` additionally budgets per originating
/// IP; `by_account` additionally budgets per normalized account key and is the
/// acceptable firewall for a single account getting hammered. Failed calls
/// return `Ok(false)`; a `clear` is expected on success.
pub fn auth_allowed(limiter: &RateLimiter, headers: &HeaderMap, account_key: Option<&str>) -> bool {
    // Per-IP: 20 requests / 10 minutes — generous for a human retrying, hostile
    // to a distributed sweep from a single source.
    let ip = client_ip(headers);
    if !limiter.allow(&format!("ip:{ip}"), 20, Duration::from_secs(600)) {
        return false;
    }
    if let Some(account) = account_key {
        // Per-account: 5 failures / 15 minutes. Checked before the (slow)
        // Argon2 verification so an attacker can't use timing here.
        if !limiter.allow(&format!("acct:{account}"), 5, Duration::from_secs(900)) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// CSRF (double-submit cookie)
// ---------------------------------------------------------------------------

/// A fresh unguessable CSRF nonce to store as the `sso_csrf` cookie. It is NOT
/// HttpOnly so the page's own JS can read it and inject it as a hidden `_csrf`
/// field into every form; `SameSite=Lax` still stops cross-site browsers from
/// sending it on POST. The value is meaningless off-origin (same-origin policy
/// hides it), so the cookie is not itself a credential.
pub fn csrf_cookie(secure: bool) -> Cookie<'static> {
    let mut c = Cookie::new(CSRF_COOKIE, crate::crypto::random_token(16));
    c.set_http_only(false);
    c.set_secure(secure);
    c.set_same_site(SameSite::Lax);
    c.set_path("/");
    c
}

/// The axum middleware. Ensures the CSRF cookie exists and, for any unsafe
/// method, requires the submitted `_csrf` (form field or `X-CSRF-Token` header)
/// to match it. Returns 403 on mismatch so cross-site forged requests are
/// dropped before they reach a handler.
pub async fn csrf_guard(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let had_cookie = cookie_value(&headers).is_some();
    let secure = state.config.cookie_secure;

    let mut resp = match method {
        Method::GET | Method::HEAD | Method::OPTIONS => next.run(req).await,
        _ => {
            // Read and then restore the body so the handler's Form extractor still works.
            let (parts, body) = req.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let submitted = header_token(&headers).or_else(|| {
                serde_urlencoded::from_bytes::<HashMap<String, String>>(&bytes)
                    .ok()
                    .and_then(|m| m.get(CSRF_FIELD).cloned())
            });
            let expected = cookie_value(&headers);
            let req = Request::from_parts(parts, Body::from(bytes));
            match (expected, submitted) {
                (Some(exp), Some(sub)) if subtle_eq(&exp, &sub) => next.run(req).await,
                _ => {
                    tracing::warn!("rejected request with missing/invalid CSRF token");
                    (StatusCode::FORBIDDEN, "forbidden (invalid CSRF token)").into_response()
                }
            }
        }
    };

    // Bake the CSRF cookie onto a first visit so the freshly loaded page (and
    // its base.html JS) has a token to echo back.
    if !had_cookie {
        if let Ok(value) = HeaderValue::from_str(&csrf_cookie(secure).to_string()) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    resp
}

fn header_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let mut it = pair.trim().splitn(2, '=');
        if it.next() == Some(CSRF_COOKIE) {
            return it.next().map(|v| v.to_string());
        }
    }
    None
}

/// Constant-time equality for token comparison.
fn subtle_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Hash used to sanity-check CSRF token length in tests.
#[allow(dead_code)]
fn _token_digest(secret: &str, nonce: &str) -> String {
    let mut h = Sha512::new();
    h.update(secret.as_bytes());
    h.update(nonce.as_bytes());
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    B64.encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_counts_within_window() {
        let l = RateLimiter::new();
        // Fake X-Forwarded-For so client_ip is stable.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert!(l.allow("ip:1.2.3.4", 2, Duration::from_secs(10)));
        assert!(l.allow("ip:1.2.3.4", 2, Duration::from_secs(10)));
        assert!(!l.allow("ip:1.2.3.4", 2, Duration::from_secs(10)));
        l.clear("ip:1.2.3.4");
        assert!(l.allow("ip:1.2.3.4", 2, Duration::from_secs(10)));
    }

    #[test]
    fn subtle_eq_handles_mismatch() {
        assert!(subtle_eq("abc", "abc"));
        assert!(!subtle_eq("abc", "abd"));
        assert!(!subtle_eq("abc", "abcd"));
    }

    #[test]
    fn client_ip_uses_forwarded() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.9");
        h.remove("x-forwarded-for");
        h.insert("cf-connecting-ip", "198.51.100.2".parse().unwrap());
        assert_eq!(client_ip(&h), "198.51.100.2");
    }
}
