package xelorra

import "fmt"

// Error is the base structured error returned by the Xelorra Go SDK.
type Error struct {
	Code    string
	Message string
	Status  int
	Reason  string
	Details map[string]any
}

func (e *Error) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("xelorra error (%s, HTTP %d): %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("xelorra error (%s): %s", e.Code, e.Message)
}

// AccessRevokedError indicates Xelorra One returned HTTP 401 access_revoked.
type AccessRevokedError struct {
	Error
}

// InsufficientScopeError indicates Xelorra One returned HTTP 403 insufficient_scope.
type InsufficientScopeError struct {
	Error
	RequiredScopes []string
}

// WebhookSignatureError indicates webhook signature or payload validation failed.
type WebhookSignatureError struct {
	Error
}
