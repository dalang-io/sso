# Dalang SSO — Python SDK

A small client for the [Dalang SSO](https://sso.example.com) OAuth 2.0 /
OpenID Connect provider. Drives the Authorization Code + PKCE flow.

```
pip install dalang-sso
```

## Usage

```python
from dalang_sso import Client, generate_pkce

# Configure with the values from your Dalang SSO dashboard.
client = Client(
    base_url="https://sso.example.com",
    client_id="CLIENT_ID",
    client_secret="CLIENT_SECRET",
    redirect_uri="https://app.example.com/callback",
)

# 1. Build the authorize URL with a fresh PKCE pair, then redirect the user's
#    browser to it. Persist pkce.verifier (e.g. in the session).
pkce = generate_pkce()
url = client.authorize_url("openid email", "state123", pkce)
print("Redirect the user to:", url)

# 2. At your callback, exchange the returned ?code=... for tokens.
tokens = client.exchange_code("CODE_FROM_CALLBACK", pkce)
print("access token:", tokens.access_token)

# 3. Fetch the user's profile.
info = client.userinfo(tokens.access_token)
print("logged in as:", info.email)

# 4. Later, refresh the access token.
if tokens.refresh_token:
    refreshed = client.refresh(tokens.refresh_token)
    print("new access token:", refreshed.access_token)
```

Omit PKCE by leaving off the `pkce` argument (it defaults to `None`).
