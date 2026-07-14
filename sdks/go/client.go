// Package dalangsso is a client SDK for Dalang SSO.
//
// It drives the OAuth 2.0 Authorization Code + PKCE flow against a self-hosted
// Dalang SSO instance. Mirrors the Google OAuth client shape: you configure a
// client_id, client_secret, and redirect_uri, then build an authorize URL,
// exchange the returned code for tokens, refresh tokens, and fetch userinfo.
package dalangsso

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Tokens is the JSON response from the token endpoint.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// UserInfo is the JSON response from the userinfo endpoint.
type UserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

// OAuthError is returned by the server on a 4xx from the token endpoint.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("oauth error: %s — %s", e.Code, e.Description)
}

// Client talks to a Dalang SSO instance.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	redirectURI  string
	HTTP         *http.Client
}

// New constructs a Client. baseURL is the SSO instance root, e.g.
// "https://sso.example.com".
func New(baseURL, clientID, clientSecret, redirectURI string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		HTTP:         http.DefaultClient,
	}
}

// AuthorizeURL builds the URL to redirect the user's browser to for consent.
// Pass a non-nil pkce to include the S256 challenge.
func (c *Client) AuthorizeURL(scope, state string, pkce *Pkce) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	if pkce != nil {
		q.Set("code_challenge", pkce.Challenge)
		q.Set("code_challenge_method", "S256")
	}
	return c.baseURL + "/oauth/authorize?" + q.Encode()
}

// ExchangeCode exchanges an authorization code for tokens. Pass a non-nil pkce
// to include the code_verifier.
func (c *Client) ExchangeCode(code string, pkce *Pkce) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	if pkce != nil {
		form.Set("code_verifier", pkce.Verifier)
	}
	return c.postToken(form)
}

// Refresh exchanges a refresh token for a fresh set of tokens.
func (c *Client) Refresh(refreshToken string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	return c.postToken(form)
}

// UserInfo fetches the profile for a given access token.
func (c *Client) UserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/oauth/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("userinfo request failed: %s", strings.TrimSpace(string(body)))
	}
	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *Client) postToken(form url.Values) (*Tokens, error) {
	resp, err := c.HTTP.PostForm(c.baseURL+"/oauth/token", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var oe OAuthError
		if err := json.Unmarshal(body, &oe); err != nil {
			return nil, fmt.Errorf("token request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil, &oe
	}
	var tokens Tokens
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}
