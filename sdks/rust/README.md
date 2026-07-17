# dalang-sso (Rust)

Client SDK for [Dalang SSO](https://github.com/dalang-io/sso). Drives the
OAuth 2.0 Authorization Code flow (with optional PKCE) and exchanges codes for
tokens against a self-hosted Dalang SSO instance.

```toml
# Cargo.toml
[dependencies]
dalang-sso = "0.2"
tokio = { version = "1", features = ["full"] }
```

## Backend (confidential client)

```rust
use dalang_sso::Client;

let sso = Client::new(
    "https://sso.example.com",              // your Dalang SSO
    "YOUR_CLIENT_ID",
    std::env::var("SSO_CLIENT_SECRET")?,    // server-side only
    "https://app.example.com/callback",
);

// 1. Redirect the user to this URL to log in
let url = sso.authorize_url("openid email", "csrf-state", None);

// 2. At your callback you receive `?code=…` — exchange it for tokens
let tokens = sso.exchange_code(&code, None).await?;
println!("access token: {}", tokens.access_token);

// later: rotate the refresh token
let refreshed = sso.refresh(tokens.refresh_token.as_deref().unwrap()).await?;
```

## Browser-style / public client (PKCE)

For public clients, generate a PKCE pair, keep the verifier, and pass the pair to
both calls:

```rust
use dalang_sso::{Client, Pkce};

let pkce = Pkce::generate();
let url = sso.authorize_url("openid email", "csrf-state", Some(&pkce));
// ... user logs in, returns with `code` ...
let tokens = sso.exchange_code(&code, Some(&pkce)).await?;
```

## API

| Method                              | Purpose                                   |
| ----------------------------------- | ----------------------------------------- |
| `Client::new(base, id, secret, redirect)` | Configure the client                |
| `authorize_url(scope, state, pkce?)`      | Build the login redirect URL        |
| `exchange_code(code, pkce?)`              | Swap an auth code for tokens        |
| `refresh(refresh_token)`                  | Rotate for a fresh token set        |
| `Pkce::generate()`                        | Create a PKCE verifier/challenge    |

Errors surface as `dalang_sso::Error` (`Http` for transport, `OAuth { code,
description }` for provider-returned errors).

> To read profile claims, decode the returned `id_token` (a standard JWT) or call
> `GET /oauth/userinfo` with the access token as a Bearer credential.
