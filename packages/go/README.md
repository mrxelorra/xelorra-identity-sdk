# Xelorra Identity Go SDK (`packages/go`)

Official Go 1.21+ SDK for **Xelorra Identity** (`https://one.xelorra.app`). Zero third-party dependencies: built exclusively on the Go standard library.

## Installation

```bash
go get github.com/xelorra/xelorra-identity-sdk/packages/go
```

## Quick Start

```go
package main

import (
	"fmt"
	"os"

	xelorra "github.com/xelorra/xelorra-identity-sdk/packages/go"
)

func main() {
	client, err := xelorra.NewClient(xelorra.ClientConfig{
		ClientID:     os.Getenv("XELORRA_CLIENT_ID"),
		ClientSecret: os.Getenv("XELORRA_CLIENT_SECRET"),
		RedirectURI:  "https://your-app.com/auth/xelorra/callback",
		Scopes:       []string{xelorra.ScopeProfileRead, xelorra.ScopePassportRead, xelorra.ScopeEmailRead},
	})
	if err != nil {
		panic(err)
	}

	signInURL, pkce, _ := client.BuildSignInURL(nil)
	signUpURL, _, _ := client.BuildSignUpURL(nil)

	fmt.Println("Sign In:", signInURL)
	fmt.Println("Sign Up:", signUpURL)
	fmt.Println("PKCE State:", pkce.State)
}
```

## Running Tests

```bash
go test -v ./...
```
