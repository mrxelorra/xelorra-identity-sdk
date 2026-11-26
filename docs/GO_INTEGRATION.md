# Go Integration Guide (`packages/go`)

The official Go SDK (`packages/go`) supports **Go 1.21+** and uses **only the Go standard library** (`net/http`, `crypto/sha256`, `crypto/hmac`, `crypto/rand`, `encoding/base64`, `encoding/json`).

## Installation

```bash
go get github.com/xelorra/xelorra-identity-sdk/packages/go
```

## Complete `net/http` Server Example

```go
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	xelorra "github.com/xelorra/xelorra-identity-sdk/packages/go"
)

func main() {
	client, err := xelorra.NewClient(xelorra.ClientConfig{
		ClientID:     os.Getenv("XELORRA_CLIENT_ID"),
		ClientSecret: os.Getenv("XELORRA_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("XELORRA_REDIRECT_URI"),
		Scopes: []string{
			xelorra.ScopeProfileRead,
			xelorra.ScopePassportRead,
			xelorra.ScopeEmailRead,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Replace with Redis or an encrypted HttpOnly cookie in production
	var mu sync.Mutex
	pkceStore := map[string]string{}

	http.HandleFunc("/auth/xelorra/login", func(w http.ResponseWriter, r *http.Request) {
		authURL, pkce, err := client.BuildSignInURL(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		pkceStore[pkce.State] = pkce.CodeVerifier
		mu.Unlock()
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/auth/xelorra/signup", func(w http.ResponseWriter, r *http.Request) {
		authURL, pkce, err := client.BuildSignUpURL(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		pkceStore[pkce.State] = pkce.CodeVerifier
		mu.Unlock()
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/auth/xelorra/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		mu.Lock()
		verifier := pkceStore[state]
		delete(pkceStore, state)
		mu.Unlock()

		if code == "" || verifier == "" {
			http.Error(w, "invalid OAuth state or code", http.StatusBadRequest)
			return
		}

		tokens, err := client.ExchangeCode(r.Context(), code, verifier, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		user, err := client.GetUserInfo(r.Context(), tokens.AccessToken)
		if err != nil {
			var revoked *xelorra.AccessRevokedError
			if errors.As(err, &revoked) {
				http.Error(w, "access revoked", http.StatusUnauthorized)
				return
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": user})
	})

	http.HandleFunc("/webhooks/xelorra", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unable to read body", http.StatusBadRequest)
			return
		}

		event, err := xelorra.ParseWebhookEvent(
			rawBody,
			r.Header.Get(xelorra.HeaderSignature),
			os.Getenv("XELORRA_WEBHOOK_SECRET"),
			300,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if event.Type == xelorra.EventUserAccessRevoked {
			log.Printf("Revoking local sessions for sub=%v", event.Data["sub"])
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"received": true, "event_type": event.Type})
	})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
