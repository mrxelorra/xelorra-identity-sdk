package xelorra

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEPair holds an RFC 7636 PKCE S256 verifier, unpadded challenge, and CSRF state.
type PKCEPair struct {
	CodeVerifier        string `json:"code_verifier"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
}

// GeneratePKCE generates a cryptographically secure PKCE S256 pair and CSRF state.
func GeneratePKCE() (PKCEPair, error) {
	verifierBytes := make([]byte, 48)
	if _, err := rand.Read(verifierBytes); err != nil {
		return PKCEPair{}, fmt.Errorf("generate code verifier: %w", err)
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	stateBytes := make([]byte, 18)
	if _, err := rand.Read(stateBytes); err != nil {
		return PKCEPair{}, fmt.Errorf("generate oauth state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	return PKCEPair{
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		State:               state,
	}, nil
}
