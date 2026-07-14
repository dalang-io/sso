# Dalang SSO

Self-hosted **OAuth 2.0 / OpenID Connect** provider in Rust — your own Google
Sign-In. Register clients in a dashboard, get a **Client ID** and **Client
Secret**, configure **Authorized JavaScript origins** and **Authorized redirect
URIs**, and drop one of the SDKs into your app. Your domain, your servers, no
Google.

- ⚡ **Fast, minimal stack** — axum + tokio, a single static binary. Stateless
  token verification (JWTs) so the app tier scales horizontally.
- 🗄️ **Any database by config** — SQLite by default (zero setup); switch to
  PostgreSQL / MySQL / MariaDB with one `DATABASE_URL`. (Oracle/MSSQL: roadmap.)
- 🖥️ **htmx + Tailwind dashboard** — manage clients, secrets, origins, redirect
  URIs. Server-rendered, no SPA build.
- 📧 **Per-client email allow-lists** — restrict a client to `@yourco.com`,
  `*@example.com`, or a specific address; empty = allow all (with a warning).
- 🔐 **Post-quantum ready** — optional ML-DSA (FIPS 204) token signing; hybrid
  ML-KEM at the TLS proxy. See [`docs/PQC.md`](docs/PQC.md).
- 📦 **SDKs** — JS/TS, Rust, Go, Python, Java, PHP in [`sdks/`](sdks/).

## Quick start

```bash
cp .env.example .env          # tweak if you like; defaults use embedded SQLite
cargo run -p sso-server       # first run bootstraps an admin from .env
# open http://localhost:8080  -> redirects to the dashboard login
```

Log in with `SSO_ADMIN_EMAIL` / `SSO_ADMIN_PASSWORD` from `.env`, create a
client, add a redirect URI, and copy the Client ID + Secret.

## How the flow works

```
  App (SDK)                  Dalang SSO                     Browser
     │  authorizeUrl() ─────────────────────────────────────►│  user consents
     │                          │◄──── GET /oauth/authorize ──┤
     │                          │──── 302 ?code=… ───────────►│
     │◄─ redirect_uri?code=… ───────────────────────────────┤
     │  exchangeCode(code) ───► POST /oauth/token             │
     │◄─ access + id + refresh token (JWT) ──────────────────┤
     │  userInfo(token) ──────► GET /oauth/userinfo           │
```

At `/oauth/authorize`, end users **log in or self-register** (accounts live in
the `users` table); the issued code is bound to the authenticated user, never to
a value the browser supplies. Supports the Authorization Code grant (with
**PKCE**), refresh-token rotation, client-credentials, OIDC discovery, JWKS, and
UserInfo.

## Endpoints

| Path                                   | Purpose                          |
| -------------------------------------- | -------------------------------- |
| `/.well-known/openid-configuration`    | OIDC discovery                   |
| `/.well-known/jwks.json`               | Public keys for token verify     |
| `/oauth/authorize`                     | Authorization + consent          |
| `/oauth/token`                         | Token endpoint (all grants)      |
| `/oauth/userinfo`                      | UserInfo (Bearer access token)   |
| `/dashboard`                           | Admin UI (client management)     |

## Documentation

- [`docs/DATABASE.md`](docs/DATABASE.md) — backends, portability, scaling
- [`docs/PQC.md`](docs/PQC.md) — post-quantum cryptography
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — production deploy + reverse proxy
- [`CLAUDE.md`](CLAUDE.md) — architecture notes for contributors

## License

Apache-2.0.
