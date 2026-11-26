package xelorra

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGeneratePKCE(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}
	if pkce.CodeChallengeMethod != "S256" {
		t.Fatalf("expected S256, got %s", pkce.CodeChallengeMethod)
	}
	if strings.Contains(pkce.CodeVerifier, "=") || strings.Contains(pkce.CodeChallenge, "=") {
		t.Fatal("PKCE values must not include '=' padding")
	}

	sum := sha256.Sum256([]byte(pkce.CodeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if pkce.CodeChallenge != expected {
		t.Fatalf("challenge mismatch: got %s want %s", pkce.CodeChallenge, expected)
	}
}

func TestBuildSignInAndSignUpURLs(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ClientID:    "acme-go-app",
		RedirectURI: "https://acme.example.com/auth/callback",
		Scopes:      []string{ScopeProfileRead, ScopeEmailRead},
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	signInURL, pkce, err := client.BuildSignInURL(nil)
	if err != nil {
		t.Fatalf("BuildSignInURL failed: %v", err)
	}
	parsedIn, _ := url.Parse(signInURL)
	if parsedIn.Host != "one.xelorra.app" || parsedIn.Path != "/oauth/authorize" {
		t.Fatalf("unexpected authorize URL: %s", signInURL)
	}
	if parsedIn.Query().Get("code_challenge") != pkce.CodeChallenge {
		t.Fatal("code_challenge mismatch")
	}
	if parsedIn.Query().Get("prompt") != "" {
		t.Fatal("sign-in URL should not set prompt")
	}

	signUpURL, _, err := client.BuildSignUpURL(&AuthorizeOptions{LoginHint: "adaeze.4821"})
	if err != nil {
		t.Fatalf("BuildSignUpURL failed: %v", err)
	}
	parsedUp, _ := url.Parse(signUpURL)
	if parsedUp.Query().Get("prompt") != "create" {
		t.Fatalf("expected prompt=create, got %s", parsedUp.Query().Get("prompt"))
	}
	if parsedUp.Query().Get("login_hint") != "adaeze.4821" {
		t.Fatal("expected login_hint to be preserved")
	}
}

func TestClientEndpointsAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["grant_type"] == "authorization_code" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "xc_at_go_1",
					"refresh_token": "xlr_rt_go_1",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"scope":         "profile.read kyc.assertion.read",
					"xid":           "XLR-9284-1039",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "xc_at_go_2",
				"refresh_token": "xlr_rt_go_2",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "profile.read kyc.assertion.read",
			})
		case "/oauth/userinfo":
			if r.Header.Get("Authorization") == "Bearer xc_at_revoked" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":             "access_revoked",
					"error_description": "Disconnected on Xelorra One",
					"reason":            "user_disconnected",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "xapp_go_1", "name": "Adaeze Okafor"})
		case "/oauth/introspect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active":    true,
				"connected": true,
				"client_id": "acme-go-app",
				"sub":       "xapp_go_1",
			})
		case "/oauth/revoke":
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case "/api/v1/verify/assertion":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verification_status":    "verified",
				"verification_type":      "government_identity",
				"verification_reference": "xvr_go_1234",
				"verified_at":            "2026-11-26T00:00:00Z",
				"credential_category":    "nin",
			})
		case "/api/v1/public/verify/qr_go_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"valid":    true,
				"xid":      "XLR-9284-1039",
				"verified": true,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := NewClient(ClientConfig{
		ClientID:    "acme-go-app",
		RedirectURI: "https://acme.example.com/auth/callback",
		Issuer:      srv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	tokens, err := client.ExchangeCode(ctx, "xc_code", "verifier_123", "")
	if err != nil || tokens.AccessToken != "xc_at_go_1" {
		t.Fatalf("ExchangeCode failed: %v", err)
	}

	connected, err := client.IsUserConnected(ctx, tokens.AccessToken)
	if err != nil || !connected {
		t.Fatalf("IsUserConnected failed: %v", err)
	}

	assertion, err := client.VerifyKYCAssertion(ctx, tokens.AccessToken)
	if err != nil || assertion.VerificationStatus != "verified" {
		t.Fatalf("VerifyKYCAssertion failed: %v", err)
	}

	passport, err := client.VerifyPassportToken(ctx, "qr_go_1", false)
	if err != nil || !passport.Valid {
		t.Fatalf("VerifyPassportToken failed: %v", err)
	}

	if _, err := client.GetUserInfo(ctx, "xc_at_revoked"); err == nil {
		t.Fatal("expected AccessRevokedError")
	} else {
		var revokedErr *AccessRevokedError
		if !errors.As(err, &revokedErr) || revokedErr.Reason != "user_disconnected" {
			t.Fatalf("expected AccessRevokedError with user_disconnected, got %v", err)
		}
	}
}

func TestWebhookVerification(t *testing.T) {
	secret := "whsec_go_secret_12345"
	now := int64(1764150000)
	rawBody := []byte(`{"id":"evt_go_1","type":"user.access_revoked","created_at":"2026-11-26T12:00:00Z","client_id":"acme-go-app","data":{"sub":"xapp_go_1","xid":"XLR-9284-1039","client_id":"acme-go-app","revoked_at":"2026-11-26T12:00:00Z","reason":"user_disconnected"}}`)

	header, err := CreateWebhookSignatureHeader(rawBody, secret, now)
	if err != nil {
		t.Fatalf("CreateWebhookSignatureHeader failed: %v", err)
	}

	if err := verifyWebhookSignatureAt(rawBody, header, secret, 300, now+120); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}

	// Tampered body fails
	tampered := []byte(strings.ReplaceAll(string(rawBody), "acme-go-app", "evil-app"))
	if err := verifyWebhookSignatureAt(tampered, header, secret, 300, now); err == nil {
		t.Fatal("expected tampered body to fail verification")
	}

	// Expired timestamp fails
	if err := verifyWebhookSignatureAt(rawBody, header, secret, 300, now+301); err == nil {
		t.Fatal("expected expired timestamp to fail verification")
	}

	// Parse valid event
	evt, err := parseWebhookEventAt(rawBody, header, secret, 300, now)
	if err != nil {
		t.Fatalf("parseWebhookEventAt failed: %v", err)
	}
	if evt.Type != EventUserAccessRevoked {
		t.Fatalf("expected %s, got %s", EventUserAccessRevoked, evt.Type)
	}
}
