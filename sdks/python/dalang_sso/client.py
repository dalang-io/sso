"""Client for the Dalang SSO OAuth 2.0 / OpenID Connect provider.

Drives the Authorization Code + PKCE flow against a self-hosted Dalang SSO
instance. Mirrors the Google OAuth client shape: you configure a client_id,
client_secret, and redirect_uri, then build an authorize URL, exchange the
returned code for tokens, refresh tokens, and fetch userinfo.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import requests


def _b64url(raw: bytes) -> str:
    """base64url-encode without padding (RFC 7636)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class Pkce:
    """A PKCE verifier/challenge pair (RFC 7636, S256)."""

    verifier: str
    challenge: str


def generate_pkce() -> Pkce:
    """Generate a random verifier and derive its S256 challenge."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return Pkce(verifier=verifier, challenge=challenge)


@dataclass
class Tokens:
    """Response from the token endpoint."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str = ""
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None

    @classmethod
    def _from_json(cls, data: dict) -> "Tokens":
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=int(data.get("expires_in", 0)),
            scope=data.get("scope", ""),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
        )


@dataclass
class UserInfo:
    """Response from the userinfo endpoint."""

    sub: str
    email: str


class OAuthError(Exception):
    """Raised when the token endpoint returns a 4xx {error, error_description}."""

    def __init__(self, code: str, description: str = ""):
        self.code = code
        self.description = description
        super().__init__(f"oauth error: {code} — {description}")


class Client:
    """Talks to a Dalang SSO instance."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        session: Optional[requests.Session] = None,
    ):
        # base_url is the SSO instance root, e.g. "https://sso.example.com".
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._http = session or requests.Session()

    def authorize_url(
        self, scope: str, state: str, pkce: Optional[Pkce] = None
    ) -> str:
        """Build the URL to redirect the user's browser to for consent."""
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
        }
        if pkce is not None:
            params["code_challenge"] = pkce.challenge
            params["code_challenge_method"] = "S256"
        return f"{self.base_url}/oauth/authorize?{urlencode(params)}"

    def exchange_code(self, code: str, pkce: Optional[Pkce] = None) -> Tokens:
        """Exchange an authorization code for tokens."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if pkce is not None:
            form["code_verifier"] = pkce.verifier
        return self._post_token(form)

    def refresh(self, refresh_token: str) -> Tokens:
        """Exchange a refresh token for a fresh set of tokens."""
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        return self._post_token(form)

    def userinfo(self, access_token: str) -> UserInfo:
        """Fetch the profile for a given access token."""
        resp = self._http.get(
            f"{self.base_url}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        data = resp.json()
        return UserInfo(sub=data["sub"], email=data.get("email", ""))

    def _post_token(self, form: dict) -> Tokens:
        resp = self._http.post(f"{self.base_url}/oauth/token", data=form)
        if resp.status_code >= 400:
            try:
                err = resp.json()
            except ValueError:
                resp.raise_for_status()
                raise
            raise OAuthError(
                err.get("error", "invalid_request"),
                err.get("error_description", ""),
            )
        return Tokens._from_json(resp.json())
