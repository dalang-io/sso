# Dalang SSO — Go SDK

A tiny, standard-library-only client for the [Dalang SSO](https://sso.example.com)
OAuth 2.0 / OpenID Connect provider. Drives the Authorization Code + PKCE flow.

```
go get github.com/dalang-io/sso/sdks/go
```

## Usage

```go
package main

import (
	"fmt"
	"log"

	dalangsso "github.com/dalang-io/sso/sdks/go"
)

func main() {
	// Configure with the values from your Dalang SSO dashboard.
	client := dalangsso.New(
		"https://sso.example.com",
		"CLIENT_ID",
		"CLIENT_SECRET",
		"https://app.example.com/callback",
	)

	// 1. Build the authorize URL with a fresh PKCE pair, then redirect the
	//    user's browser to it. Persist pkce.Verifier (e.g. in the session).
	pkce, err := dalangsso.GeneratePkce()
	if err != nil {
		log.Fatal(err)
	}
	url := client.AuthorizeURL("openid email", "state123", pkce)
	fmt.Println("Redirect the user to:", url)

	// 2. At your callback, exchange the returned ?code=... for tokens.
	tokens, err := client.ExchangeCode("CODE_FROM_CALLBACK", pkce)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("access token:", tokens.AccessToken)

	// 3. Fetch the user's profile.
	info, err := client.UserInfo(tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("logged in as:", info.Email)

	// 4. Later, refresh the access token.
	if tokens.RefreshToken != "" {
		refreshed, err := client.Refresh(tokens.RefreshToken)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("new access token:", refreshed.AccessToken)
	}
}
```

Omit PKCE by passing `nil` in place of the `*Pkce` argument.
