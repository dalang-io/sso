/**
 * JavaScript/TypeScript client SDK for Dalang SSO.
 *
 * Works in the browser and in modern Node (>=18, for global `fetch` and
 * WebCrypto). Mirrors the Google OAuth client shape: configure `clientId`,
 * `clientSecret` (server-side only), and `redirectUri`, then run the
 * Authorization Code + PKCE flow against your self-hosted Dalang SSO instance.
 *
 * Browser (public client) usage — never ship a client secret to the browser;
 * rely on PKCE and exchange the code from your backend:
 *
 *   const sso = new DalangSSO({ baseUrl, clientId, redirectUri });
 *   const pkce = await generatePkce();
 *   sessionStorage.setItem("pkce_verifier", pkce.verifier);
 *   location.href = sso.authorizeUrl({ scope: "openid email", state, pkce });
 */

export interface DalangSSOOptions {
  baseUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
}

export interface Pkce {
  verifier: string;
  challenge: string;
}

export interface Tokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

export interface UserInfo {
  sub: string;
  email: string;
  [key: string]: unknown;
}

export class OAuthError extends Error {
  constructor(public code: string, public description: string) {
    super(`${code}: ${description}`);
    this.name = "OAuthError";
  }
}

const b64url = (bytes: ArrayBuffer): string => {
  const bin = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** Generate an RFC 7636 PKCE verifier/challenge pair (S256). */
export async function generatePkce(): Promise<Pkce> {
  const random = crypto.getRandomValues(new Uint8Array(32));
  const verifier = b64url(random.buffer);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(digest) };
}

export class DalangSSO {
  private readonly baseUrl: string;
  constructor(private readonly opts: DalangSSOOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
  }

  /** Build the URL to send the user's browser to for consent. */
  authorizeUrl(params: { scope: string; state: string; pkce?: Pkce }): string {
    const q = new URLSearchParams({
      response_type: "code",
      client_id: this.opts.clientId,
      redirect_uri: this.opts.redirectUri,
      scope: params.scope,
      state: params.state,
    });
    if (params.pkce) {
      q.set("code_challenge", params.pkce.challenge);
      q.set("code_challenge_method", "S256");
    }
    return `${this.baseUrl}/oauth/authorize?${q.toString()}`;
  }

  /** Exchange an authorization code for tokens (call from your backend). */
  async exchangeCode(code: string, codeVerifier?: string): Promise<Tokens> {
    const body: Record<string, string> = {
      grant_type: "authorization_code",
      code,
      redirect_uri: this.opts.redirectUri,
      client_id: this.opts.clientId,
    };
    if (this.opts.clientSecret) body.client_secret = this.opts.clientSecret;
    if (codeVerifier) body.code_verifier = codeVerifier;
    return this.postToken(body);
  }

  /** Exchange a refresh token for a fresh token set. */
  async refresh(refreshToken: string): Promise<Tokens> {
    const body: Record<string, string> = {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.opts.clientId,
    };
    if (this.opts.clientSecret) body.client_secret = this.opts.clientSecret;
    return this.postToken(body);
  }

  /** Fetch the profile for the subject bound to an access token. */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const res = await fetch(`${this.baseUrl}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) throw new OAuthError("invalid_token", `HTTP ${res.status}`);
    return res.json();
  }

  private async postToken(body: Record<string, string>): Promise<Tokens> {
    const res = await fetch(`${this.baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString(),
    });
    const json = await res.json();
    if (!res.ok) throw new OAuthError(json.error ?? "error", json.error_description ?? "");
    return json as Tokens;
  }
}
