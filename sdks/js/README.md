# @dalang-io/sso (JavaScript / TypeScript)

Client SDK for [Dalang SSO](https://github.com/dalang-io/sso). Works in the
browser and in Node ≥ 18.

```bash
npm install @dalang-io/sso
```

## Browser (public client, PKCE — no secret)

```ts
import { DalangSSO, generatePkce } from "@dalang-io/sso";

const sso = new DalangSSO({
  baseUrl: "https://sso.example.com",
  clientId: "YOUR_CLIENT_ID",
  redirectUri: "https://app.example.com/callback",
});

// 1. Start login
const pkce = await generatePkce();
sessionStorage.setItem("pkce_verifier", pkce.verifier);
location.href = sso.authorizeUrl({ scope: "openid email", state: "xyz", pkce });
```

## Backend (confidential client) — exchange the code

```ts
const sso = new DalangSSO({
  baseUrl: "https://sso.example.com",
  clientId: "YOUR_CLIENT_ID",
  clientSecret: process.env.SSO_CLIENT_SECRET, // server-side only
  redirectUri: "https://app.example.com/callback",
});

const tokens = await sso.exchangeCode(code, codeVerifier);
const me = await sso.userInfo(tokens.access_token);
// later:
const refreshed = await sso.refresh(tokens.refresh_token!);
```

> Never expose `clientSecret` in browser code. Public browser clients should use
> PKCE and exchange the authorization code from a backend.
