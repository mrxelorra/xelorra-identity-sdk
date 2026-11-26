package xelorra

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientConfig configures a Xelorra Identity SDK client.
type ClientConfig struct {
	ClientID     string
	RedirectURI  string
	ClientSecret string
	Issuer       string
	BaseURL      string
	Scopes       []string
	HTTPClient   *http.Client
}

// AuthorizeOptions customizes an OAuth 2.0 + PKCE S256 authorization URL.
type AuthorizeOptions struct {
	Scopes      []string
	State       string
	PKCE        *PKCEPair
	RedirectURI string
	Prompt      string
	LoginHint   string
	ExtraParams map[string]string
}

// TokenSet represents the JSON payload returned by POST /oauth/token.
type TokenSet struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	Scope        string  `json:"scope"`
	XID          *string `json:"xid,omitempty"`
}

// IntrospectionResult represents the JSON payload returned by POST /oauth/introspect.
type IntrospectionResult struct {
	Active    bool    `json:"active"`
	Connected bool    `json:"connected"`
	ClientID  *string `json:"client_id,omitempty"`
	Sub       *string `json:"sub,omitempty"`
	XID       *string `json:"xid,omitempty"`
	Scope     *string `json:"scope,omitempty"`
	Exp       *int64  `json:"exp,omitempty"`
	Reason    *string `json:"reason,omitempty"`
}

// KYCAssertion represents the minimum-disclosure response from POST /api/v1/verify/assertion.
type KYCAssertion struct {
	VerificationStatus    string  `json:"verification_status"`
	VerificationType      string  `json:"verification_type"`
	VerificationReference *string `json:"verification_reference"`
	VerifiedAt            *string `json:"verified_at"`
	CredentialCategory    string  `json:"credential_category,omitempty"`
}

// PassportVerificationResult represents the public zero-PII QR verification response.
type PassportVerificationResult struct {
	Valid        bool     `json:"valid"`
	Reason       string   `json:"reason,omitempty"`
	XID          string   `json:"xid,omitempty"`
	Name         string   `json:"name,omitempty"`
	Tier         string   `json:"tier,omitempty"`
	Status       string   `json:"status,omitempty"`
	Verified     bool     `json:"verified,omitempty"`
	MemberSince  string   `json:"memberSince,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	ExpiresAt    string   `json:"expiresAt,omitempty"`
	CheckedAt    string   `json:"checkedAt,omitempty"`
	SharedFields []string `json:"sharedFields,omitempty"`
	Disclaimer   string   `json:"disclaimer,omitempty"`
}

// XIDAvailabilityResult represents GET /api/v1/xid/check?username=<handle>.
type XIDAvailabilityResult struct {
	Available   bool     `json:"available"`
	Suggestions []string `json:"suggestions,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// RevokeResult represents POST /oauth/revoke.
type RevokeResult struct {
	Revoked bool `json:"revoked"`
}

// LogoutResult represents POST /oauth/logout.
type LogoutResult struct {
	LoggedOut bool   `json:"loggedOut"`
	Message   string `json:"message,omitempty"`
}

// Client interacts with https://one.xelorra.app using only the Go standard library.
type Client struct {
	ClientID     string
	RedirectURI  string
	ClientSecret string
	Issuer       string
	Scopes       []string
	httpClient   *http.Client
}

// NewClient validates configuration and returns a new Xelorra Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, &Error{Code: "invalid_config", Message: "ClientID is required."}
	}

	rawIssuer := strings.TrimSpace(cfg.Issuer)
	if rawIssuer == "" {
		rawIssuer = strings.TrimSpace(cfg.BaseURL)
	}
	if rawIssuer == "" {
		rawIssuer = DefaultIssuer
	}
	rawIssuer = strings.TrimRight(rawIssuer, "/")

	parsed, err := url.Parse(rawIssuer)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, &Error{Code: "invalid_config", Message: "Issuer must be a valid http(s) URL."}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &Client{
		ClientID:     clientID,
		RedirectURI:  strings.TrimSpace(cfg.RedirectURI),
		ClientSecret: strings.TrimSpace(cfg.ClientSecret),
		Issuer:       rawIssuer,
		Scopes:       append([]string(nil), scopes...),
		httpClient:   httpClient,
	}, nil
}

// BuildSignInURL builds a Sign In authorization URL targeting GET /oauth/authorize.
func (c *Client) BuildSignInURL(opts *AuthorizeOptions) (string, PKCEPair, error) {
	return c.BuildAuthorizeURL(opts)
}

// BuildSignUpURL builds a Sign Up authorization URL (`prompt=create`) targeting GET /oauth/authorize.
func (c *Client) BuildSignUpURL(opts *AuthorizeOptions) (string, PKCEPair, error) {
	var copyOpts AuthorizeOptions
	if opts != nil {
		copyOpts = *opts
	}
	copyOpts.Prompt = "create"
	return c.BuildAuthorizeURL(&copyOpts)
}

// BuildAuthorizeURL builds an OAuth 2.0 + PKCE S256 authorization URL.
func (c *Client) BuildAuthorizeURL(opts *AuthorizeOptions) (string, PKCEPair, error) {
	var o AuthorizeOptions
	if opts != nil {
		o = *opts
	}

	redirectURI := strings.TrimSpace(o.RedirectURI)
	if redirectURI == "" {
		redirectURI = c.RedirectURI
	}
	if redirectURI == "" {
		return "", PKCEPair{}, &Error{
			Code:    "invalid_config",
			Message: "RedirectURI is required for OAuth authorization.",
		}
	}

	var pair PKCEPair
	if o.PKCE != nil {
		pair = *o.PKCE
	} else {
		generated, err := GeneratePKCE()
		if err != nil {
			return "", PKCEPair{}, err
		}
		pair = generated
	}

	state := strings.TrimSpace(o.State)
	if state == "" {
		state = pair.State
	}
	pair.State = state

	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = c.Scopes
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", pair.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if o.Prompt != "" {
		q.Set("prompt", o.Prompt)
	}
	if o.LoginHint != "" {
		q.Set("login_hint", o.LoginHint)
	}
	for k, v := range o.ExtraParams {
		q.Set(k, v)
	}

	return c.Issuer + "/oauth/authorize?" + q.Encode(), pair, nil
}

// FetchDiscovery fetches GET /.well-known/openid-configuration.
func (c *Client) FetchDiscovery(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/.well-known/openid-configuration", nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchJWKS fetches GET /.well-known/jwks.json.
func (c *Client) FetchJWKS(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/.well-known/jwks.json", nil, nil, &out, false); err != nil {
		return nil, err
	}
	return out, nil
}

// ExchangeCode exchanges an authorization code and PKCE verifier via POST /oauth/token.
func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*TokenSet, error) {
	if strings.TrimSpace(code) == "" {
		return nil, &Error{Code: "missing_code", Message: "Authorization code is required."}
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, &Error{Code: "missing_pkce_verifier", Message: "codeVerifier is required."}
	}
	resolvedRedirect := strings.TrimSpace(redirectURI)
	if resolvedRedirect == "" {
		resolvedRedirect = c.RedirectURI
	}
	if resolvedRedirect == "" {
		return nil, &Error{Code: "invalid_config", Message: "RedirectURI is required."}
	}

	payload := map[string]string{
		"grant_type":    "authorization_code",
		"code":          strings.TrimSpace(code),
		"client_id":     c.ClientID,
		"redirect_uri":  resolvedRedirect,
		"code_verifier": strings.TrimSpace(codeVerifier),
	}
	if c.ClientSecret != "" {
		payload["client_secret"] = c.ClientSecret
	}

	var out TokenSet
	if err := c.doJSON(ctx, http.MethodPost, "/oauth/token", nil, payload, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// RefreshTokens rotates a single-use refresh token via POST /oauth/token.
func (c *Client) RefreshTokens(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, &Error{Code: "missing_refresh_token", Message: "refreshToken is required."}
	}

	payload := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": strings.TrimSpace(refreshToken),
		"client_id":     c.ClientID,
	}
	if c.ClientSecret != "" {
		payload["client_secret"] = c.ClientSecret
	}

	var out TokenSet
	if err := c.doJSON(ctx, http.MethodPost, "/oauth/token", nil, payload, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetUserInfo loads granted user claims from GET /oauth/userinfo.
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, &Error{Code: "unauthenticated", Message: "accessToken is required."}
	}

	var out map[string]any
	headers := map[string]string{"Authorization": "Bearer " + strings.TrimSpace(accessToken)}
	if err := c.doJSON(ctx, http.MethodGet, "/oauth/userinfo", headers, nil, &out, false); err != nil {
		return nil, err
	}
	return out, nil
}

// IntrospectToken verifies live token and connection status via POST /oauth/introspect.
func (c *Client) IntrospectToken(ctx context.Context, accessToken string) (*IntrospectionResult, error) {
	trimmed := strings.TrimSpace(accessToken)
	if trimmed == "" {
		reason := "missing_token"
		return &IntrospectionResult{Active: false, Connected: false, Reason: &reason}, nil
	}

	payload := map[string]string{
		"token":     trimmed,
		"client_id": c.ClientID,
	}
	if c.ClientSecret != "" {
		payload["client_secret"] = c.ClientSecret
	}

	var out IntrospectionResult
	if err := c.doJSON(ctx, http.MethodPost, "/oauth/introspect", nil, payload, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// IsUserConnected returns true only when POST /oauth/introspect confirms active and connected.
func (c *Client) IsUserConnected(ctx context.Context, accessToken string) (bool, error) {
	res, err := c.IntrospectToken(ctx, accessToken)
	if err != nil {
		return false, err
	}
	return res.Active && res.Connected, nil
}

// RevokeToken revokes an access or refresh token via POST /oauth/revoke.
func (c *Client) RevokeToken(ctx context.Context, token string) (*RevokeResult, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return &RevokeResult{Revoked: true}, nil
	}

	payload := map[string]string{
		"token":     trimmed,
		"client_id": c.ClientID,
	}
	if c.ClientSecret != "" {
		payload["client_secret"] = c.ClientSecret
	}

	var out RevokeResult
	if err := c.doJSON(ctx, http.MethodPost, "/oauth/revoke", nil, payload, &out, false); err != nil {
		return nil, err
	}
	if !out.Revoked {
		out.Revoked = true
	}
	return &out, nil
}

// Logout revokes the provided token (if any) and calls POST /oauth/logout.
func (c *Client) Logout(ctx context.Context, accessToken string) (*LogoutResult, error) {
	headers := map[string]string{}
	if strings.TrimSpace(accessToken) != "" {
		if _, err := c.RevokeToken(ctx, accessToken); err != nil {
			return nil, err
		}
		headers["Authorization"] = "Bearer " + strings.TrimSpace(accessToken)
	}

	var out LogoutResult
	if err := c.doJSON(ctx, http.MethodPost, "/oauth/logout", headers, map[string]string{"client_id": c.ClientID}, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyKYCAssertion calls POST /api/v1/verify/assertion for minimum-disclosure KYC status.
func (c *Client) VerifyKYCAssertion(ctx context.Context, accessToken string) (*KYCAssertion, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, &Error{Code: "unauthenticated", Message: "accessToken is required."}
	}

	headers := map[string]string{"Authorization": "Bearer " + strings.TrimSpace(accessToken)}
	var out KYCAssertion
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/verify/assertion", headers, map[string]any{}, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyPassportToken verifies a short-lived rotating Digital Passport QR token without auth.
// Set selective=true to query GET /api/v1/verify/:token instead of GET /api/v1/public/verify/:token.
func (c *Client) VerifyPassportToken(ctx context.Context, token string, selective bool) (*PassportVerificationResult, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return nil, &Error{Code: "invalid_token", Message: "Passport QR token is required."}
	}

	escaped := url.PathEscape(trimmed)
	path := "/api/v1/public/verify/" + escaped
	if selective {
		path = "/api/v1/verify/" + escaped
	}

	var out PassportVerificationResult
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckXIDAvailability checks memorable XID handle availability via GET /api/v1/xid/check.
func (c *Client) CheckXIDAvailability(ctx context.Context, username string) (*XIDAvailabilityResult, error) {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return nil, &Error{Code: "invalid_request", Message: "username is required."}
	}

	path := "/api/v1/xid/check?username=" + url.QueryEscape(trimmed)
	var out XIDAvailabilityResult
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	headers map[string]string,
	body any,
	dest any,
	allowPassportPayload bool,
) error {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.Issuer+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &Error{Code: "network_error", Message: err.Error()}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{Code: "network_error", Message: err.Error()}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if dest != nil && len(bytes.TrimSpace(raw)) > 0 {
			return json.Unmarshal(raw, dest)
		}
		return nil
	}

	var details map[string]any
	_ = json.Unmarshal(raw, &details)

	if allowPassportPayload {
		if _, hasValid := details["valid"]; hasValid && dest != nil {
			return json.Unmarshal(raw, dest)
		}
	}

	errCode, _ := details["error"].(string)
	if errCode == "" {
		errCode = "request_failed"
	}
	errDesc, _ := details["error_description"].(string)
	if errDesc == "" {
		if msg, ok := details["message"].(string); ok && msg != "" {
			errDesc = msg
		} else {
			errDesc = "Xelorra API request failed."
		}
	}
	reason, _ := details["reason"].(string)

	base := Error{
		Code:    errCode,
		Message: errDesc,
		Status:  resp.StatusCode,
		Reason:  reason,
		Details: details,
	}

	if resp.StatusCode == http.StatusUnauthorized && errCode == "access_revoked" {
		return &AccessRevokedError{Error: base}
	}
	if resp.StatusCode == http.StatusForbidden && errCode == "insufficient_scope" {
		return &InsufficientScopeError{Error: base}
	}

	return &base
}
