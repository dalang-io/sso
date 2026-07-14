# Dalang SSO — Java SDK

A small client for the [Dalang SSO](https://sso.example.com) OAuth 2.0 /
OpenID Connect provider, built on `java.net.http.HttpClient`. Drives the
Authorization Code + PKCE flow.

Requires Java 17+. Add it via Maven:

```xml
<dependency>
    <groupId>io.dalang</groupId>
    <artifactId>dalang-sso</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import io.dalang.sso.Pkce;
import io.dalang.sso.SsoClient;

// Configure with the values from your Dalang SSO dashboard.
SsoClient client = new SsoClient(
        "https://sso.example.com",
        "CLIENT_ID",
        "CLIENT_SECRET",
        "https://app.example.com/callback");

// 1. Build the authorize URL with a fresh PKCE pair, then redirect the user's
//    browser to it. Persist pkce.verifier (e.g. in the session).
Pkce pkce = Pkce.generate();
String url = client.authorizeUrl("openid email", "state123", pkce);
System.out.println("Redirect the user to: " + url);

// 2. At your callback, exchange the returned ?code=... for tokens.
SsoClient.Tokens tokens = client.exchangeCode("CODE_FROM_CALLBACK", pkce);
System.out.println("access token: " + tokens.accessToken);

// 3. Fetch the user's profile.
SsoClient.UserInfo info = client.userInfo(tokens.accessToken);
System.out.println("logged in as: " + info.email);

// 4. Later, refresh the access token.
if (tokens.refreshToken != null) {
    SsoClient.Tokens refreshed = client.refresh(tokens.refreshToken);
    System.out.println("new access token: " + refreshed.accessToken);
}
```

Omit PKCE by passing `null` in place of the `Pkce` argument.
