# Dalang SSO

> **Your own "Sign in with Google" — self-hosted.** An open-source OAuth 2.0 /
> OpenID Connect identity provider you run on your own servers. A lightweight
> alternative to Keycloak, Auth0, and Okta.

[![Release](https://img.shields.io/github/v/release/dalang-io/sso?sort=semver)](https://github.com/dalang-io/sso/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)](https://www.rust-lang.org/)

Add "Log in with your company account" to any app. Register the app once in a
web dashboard, copy its **Client ID** and **Client Secret**, drop in one of the
six SDKs, and your users sign in through **your** domain — no third-party
identity provider, no per-user billing, no data leaving your infrastructure.

It ships as a **single self-contained binary**: no runtime, no build step, no
external services. Start it, open the browser, done.

```
   Your app  ──"log in"──►  Dalang SSO  ──►  user signs in  ──►  back to your app
  (any language)          (your server)     (your login page)    (with an ID token)
```

---

## Table of contents

- [Highlights](#highlights)
- [Quickstart (2 minutes)](#quickstart-2-minutes)
- [Connect your first app](#connect-your-first-app)
- [How the login flow works](#how-the-login-flow-works)
- [SDKs](#sdks)
- [Endpoints](#endpoints)
- [Multi-tenancy & roles](#multi-tenancy--roles)
- [Security](#security)
- [Production deployment](#production-deployment)
- [Databases](#databases)
- [Configuration](#configuration)
- [FAQ](#faq)
- [Documentation](#documentation)
- [License](#license)

---

## Highlights

**For developers**

- ⚡ **One binary, zero setup** — axum + tokio compiled to a static executable.
  SQLite is embedded by default, so `./sso` just works.
- 🔌 **Standards-based** — plain OAuth 2.0 / OpenID Connect (Authorization Code
  + PKCE, refresh tokens, client credentials, discovery, JWKS, UserInfo). Works
  with any OIDC-compliant library, not just our SDKs.
- 📦 **Six official SDKs** — JavaScript/TypeScript, Rust, Go, Python, Java, PHP.
- 🖥️ **Server-rendered dashboard** — manage apps, secrets, origins, and redirect
  URIs. No SPA build, no separate frontend to deploy.

**For enterprises**

- 🏢 **Self-hosted & data-sovereign** — every account, token, and log stays on
  your servers. Airgap-friendly: all assets are bundled, nothing phones home.
- 🏬 **Multi-tenant with RBAC** — isolated workspaces (tenants) and three
  dashboard roles (super / manager / developer). See [below](#multi-tenancy--roles).
- 📈 **Scales horizontally** — stateless app tier (token verification never hits
  the database); run N nodes behind a load balancer. Designed for very high
  concurrency.
- 🔐 **Security-first & post-quantum ready** — PKCE, rotating refresh tokens with
  reuse detection, per-client email allow-lists, hardened HTTP headers, and
  optional ML-DSA (FIPS 204) post-quantum token signing.
- 🗄️ **Bring your own database** — SQLite, PostgreSQL, or MySQL/MariaDB, chosen
  by one `DATABASE_URL` — no recompile.

---

## Quickstart (2 minutes)

You'll have a running SSO with an admin account in under two minutes. Pick one:

### Option A — Prebuilt binary (no Rust toolchain needed)

Download the binary for your platform from the
[**latest release**](https://github.com/dalang-io/sso/releases/latest), then:

```bash
# Linux x86_64 example — adjust the asset name for your OS/arch
curl -L -o sso https://github.com/dalang-io/sso/releases/latest/download/sso-linux-x86_64
chmod +x sso
./sso
```

Prebuilt assets: `sso-linux-x86_64`, `sso-linux-arm64`, `sso-macos-arm64`,
`sso-macos-x86_64`. Each has a `.sha256` alongside it to verify the download.

### Option B — From source (needs Rust)

```bash
git clone https://github.com/dalang-io/sso.git
cd sso
cargo run -p sso-server        # first build takes a minute; then instant
```

### Then — create your admin

Both options start the server on **http://localhost:8080** with an embedded
SQLite database (auto-created). On first run there is **no default admin** —
open the one-time setup page and create the super admin:

👉 **Open http://localhost:8080/setup** and pick an email + password.

That's it. You land in the dashboard, ready to register your first app.

> **Config is optional for local dev.** To customize (database, public URL,
> secrets, branding), copy `.env.example` to `.env` and edit — see
> [Configuration](#configuration).

---

## Connect your first app

A worked example: adding login to a Node.js web app. The same five steps apply
in any language — only the SDK call syntax changes.

**1. Register the app** in the dashboard (`/dashboard` → **New client**). Give it
a name; you'll get a **Client ID** and a one-time **Client Secret** (copy it now
— it's shown only once).

**2. Add a redirect URI** on the client page — the URL Dalang SSO sends users
back to after they log in, e.g. `http://localhost:3000/callback`. Redirect URIs
are matched **exactly**.

**3. Install the SDK:**

```bash
npm install @dalang-io/sso
```

**4. Send users to the login page** and **5. handle the callback.** A minimal
Express server:

```ts
import express from "express";
import { DalangSSO } from "@dalang-io/sso";

const sso = new DalangSSO({
  baseUrl: "http://localhost:8080",            // your Dalang SSO
  clientId: process.env.SSO_CLIENT_ID!,
  clientSecret: process.env.SSO_CLIENT_SECRET!, // server-side only, never in a browser
  redirectUri: "http://localhost:3000/callback",
});

const app = express();

// 4. Start login → redirect the user to Dalang SSO
app.get("/login", (_req, res) => {
  res.redirect(sso.authorizeUrl({ scope: "openid email", state: "csrf-token" }));
});

// 5. User comes back with ?code=… → exchange it for tokens
app.get("/callback", async (req, res) => {
  const tokens = await sso.exchangeCode(String(req.query.code));
  const user = await sso.userInfo(tokens.access_token);
  res.json({ signedInAs: user.email });   // now create your app session
});

app.listen(3000);
```

Open `http://localhost:3000/login` → you're taken to your SSO's login/consent
screen → back to your app, signed in. Full SDK docs (including browser-only PKCE
flows) live in [`sdks/`](sdks/).

---

## How the login flow works

Standard OIDC Authorization Code flow. The SDK builds the URLs and does the token
exchange for you:

```
  Your app (SDK)             Dalang SSO                        Browser / user
     │  authorizeUrl() ───────────────────────────────────────►│  logs in + consents
     │                          │◄──── GET /oauth/authorize ────┤
     │                          │───── 302 back with ?code=… ──►│
     │◄─ redirect_uri?code=… ──────────────────────────────────┤
     │  exchangeCode(code) ────► POST /oauth/token              │
     │◄─ access + id + refresh token (JWT) ────────────────────┤
     │  userInfo(token) ───────► GET /oauth/userinfo            │
```

End users **log in or self-register** at `/oauth/authorize` (their accounts live
in the `users` table, separate from dashboard admins). The authorization code is
bound to the **authenticated session** — never to a value the browser supplies —
so a client can never choose whom it logs in as.

---

## SDKs

Same small surface everywhere: build an authorize URL → exchange the code →
refresh tokens (and read the user via the ID token or `/oauth/userinfo`).

| Language          | Package                        | Docs                                     |
| ----------------- | ------------------------------ | ---------------------------------------- |
| JavaScript / TS   | `@dalang-io/sso`               | [sdks/js](sdks/js/README.md)             |
| Rust              | `dalang-sso`                   | [sdks/rust](sdks/rust)                   |
| Go                | `github.com/dalang-io/sso/...` | [sdks/go](sdks/go/README.md)             |
| Python            | `dalang-sso`                   | [sdks/python](sdks/python/README.md)     |
| Java              | `io.dalang:sso`                | [sdks/java](sdks/java/README.md)         |
| PHP               | `dalang-io/sso`                | [sdks/php](sdks/php/README.md)           |

No SDK for your stack? Any OIDC-compliant library works — point it at
`/.well-known/openid-configuration`.

---

## Endpoints

| Path                                | Purpose                              |
| ----------------------------------- | ------------------------------------ |
| `/.well-known/openid-configuration` | OIDC discovery document              |
| `/.well-known/jwks.json`            | Public keys for verifying tokens     |
| `/oauth/authorize`                  | Login, consent, and code issuance    |
| `/oauth/token`                      | Token endpoint (all grants)          |
| `/oauth/userinfo`                   | UserInfo (Bearer access token)       |
| `/dashboard`                        | Admin dashboard (manage apps)        |
| `/setup`                            | One-time first-admin onboarding      |

---

## Multi-tenancy & roles

Organize clients into isolated **tenants** (workspaces) and invite members with
scoped permissions — the server enforces every boundary (the UI only hides what
a role can't do).

| Role          | Scope        | Can do                                                    |
| ------------- | ------------ | --------------------------------------------------------- |
| **super**     | Global       | Everything: manage tenants, members, and all clients      |
| **manager**   | Own tenant   | Create/delete clients, edit config, manage secrets        |
| **developer** | Own tenant   | Add/rotate/delete client secrets only (no client changes) |

Cross-tenant access returns `404`; disallowed actions return `403`.

---

## Security

- **Authorization Code + PKCE**, refresh-token rotation with **reuse detection**
  (a replayed refresh token revokes the whole token family), and single-use,
  atomically-consumed authorization codes.
- **Stateless JWTs** — access/ID tokens are self-verifying (RS256 or ML-DSA);
  verifying a token never touches the database.
- **Per-client email allow-lists** — restrict an app to `@yourco.com`,
  `*@example.com`, or a single address (empty = allow everyone, with a warning).
- **Hardened by default** — `Secure` session cookies, clickjacking protection on
  the consent screen (`X-Frame-Options` / CSP `frame-ancestors`), HSTS, and a
  fail-closed check that refuses to boot with a placeholder session secret when
  exposed beyond localhost.
- **Post-quantum option** — switch token signing to ML-DSA-65 (FIPS 204) with one
  env var; hybrid ML-KEM at the TLS proxy. See [`docs/PQC.md`](docs/PQC.md).

---

## Production deployment

Dalang SSO is one static binary behind a TLS-terminating reverse proxy. In short:

1. Put the binary + a `.env` on your server (or use [`deploy/deploy.sh`](deploy/deploy.sh)).
2. Set real secrets: `openssl rand -hex 32` → `SSO_SESSION_SECRET`, and a
   persistent RSA key for `SSO_JWT_PRIVATE_KEY_PATH` (so tokens survive restarts).
3. Set `SSO_PUBLIC_URL` to your public HTTPS origin (it becomes the OIDC issuer).
4. Terminate TLS in front (Caddy, Nginx, or a CDN) and open `/setup` once.

Full guide, systemd unit, reverse-proxy configs, and horizontal-scaling notes:
[**`docs/DEPLOY.md`**](docs/DEPLOY.md).

---

## Databases

One `DATABASE_URL` picks the driver at runtime — no recompile:

```env
DATABASE_URL=sqlite://data/sso.db?mode=rwc      # default, zero-setup
DATABASE_URL=postgres://user:pass@host:5432/sso # PostgreSQL
DATABASE_URL=mysql://user:pass@host:3306/sso    # MySQL / MariaDB
```

For multi-node deployments, point at Postgres/MySQL and run read replicas — the
app tier is stateless. Details: [`docs/DATABASE.md`](docs/DATABASE.md).

---

## Configuration

Every setting is an environment variable with a sensible default;
[`.env.example`](.env.example) is the fully-commented reference. Most-used knobs:

| Variable                   | Default                  | What it does                                  |
| -------------------------- | ------------------------ | --------------------------------------------- |
| `SSO_BIND_ADDR`            | `127.0.0.1:8080`         | Address to listen on (`0.0.0.0` in prod)      |
| `SSO_PUBLIC_URL`           | `http://localhost:8080`  | Public origin → OIDC issuer + absolute URLs   |
| `DATABASE_URL`             | embedded SQLite          | Storage backend (see above)                   |
| `SSO_SESSION_SECRET`       | dev default (localhost)  | Cookie signing key — **required** in prod     |
| `SSO_JWT_PRIVATE_KEY_PATH` | ephemeral                | Persistent RSA key — **set for prod**         |
| `SSO_TOKEN_SIGNING_ALG`    | `rs256`                  | `rs256` or `ml-dsa-65` (post-quantum)         |
| `SSO_BRAND_TITLE` / `_LOGO_PATH` / `_FAVICON_PATH` | Dalang branding | White-label the dashboard      |

---

## FAQ

**Is this a Keycloak / Auth0 / Okta replacement?**
For the core "let users log into my apps with OAuth/OIDC" job, yes — with a far
smaller footprint (one binary vs. a JVM/cluster) and no per-user pricing. It
focuses on OAuth2/OIDC; it is not a full IAM suite (no SAML/LDAP federation).

**Do I have to use Rust?**
No. Download a prebuilt binary and integrate from any language via the SDKs or
any OIDC library.

**Where is user data stored?**
Wherever you point `DATABASE_URL`. Nothing leaves your infrastructure; all UI
assets are bundled for airgapped environments.

**Can it handle many users?**
The app tier is stateless and token verification is DB-free, so you scale by
adding nodes behind a load balancer with a shared secret + signing key.

---

## Documentation

- [`docs/DEPLOY.md`](docs/DEPLOY.md) — production deploy, reverse proxy, scaling
- [`docs/DATABASE.md`](docs/DATABASE.md) — backends, portability, replicas
- [`docs/PQC.md`](docs/PQC.md) — post-quantum cryptography & threat model
- [`CLAUDE.md`](CLAUDE.md) — architecture notes for contributors

---

## License

[Apache-2.0](LICENSE).
