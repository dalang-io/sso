package dalangsso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Pkce is a PKCE verifier/challenge pair (RFC 7636, S256).
type Pkce struct {
	Verifier  string
	Challenge string
}

// GeneratePkce creates a random verifier and derives its S256 challenge:
// challenge = base64url(sha256(verifier)) with no padding.
func GeneratePkce() (*Pkce, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return &Pkce{Verifier: verifier, Challenge: challenge}, nil
}
