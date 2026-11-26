package xelorra

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WebhookEvent represents a signed JSON webhook envelope sent by Xelorra One.
type WebhookEvent struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt string         `json:"created_at"`
	ClientID  string         `json:"client_id"`
	Data      map[string]any `json:"data"`
}

// CreateWebhookSignatureHeader generates `t=<unix_seconds>,v1=<hmac_sha256_hex>` for testing.
func CreateWebhookSignatureHeader(rawBody []byte, signingSecret string, timestampSeconds int64) (string, error) {
	if signingSecret == "" {
		return "", &WebhookSignatureError{
			Error: Error{
				Code:    "missing_webhook_secret",
				Message: "signingSecret is required to compute a webhook signature.",
				Status:  401,
			},
		}
	}
	if timestampSeconds <= 0 {
		timestampSeconds = time.Now().Unix()
	}

	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(strconv.FormatInt(timestampSeconds, 10)))
	mac.Write([]byte("."))
	mac.Write(rawBody)

	return fmt.Sprintf("t=%d,v1=%s", timestampSeconds, hex.EncodeToString(mac.Sum(nil))), nil
}

// VerifyWebhookSignature validates `X-Xelorra-Signature: t=<unix_ts>,v1=<hmac_sha256_hex>`
// using hmac.Equal and replay-window tolerance (defaults to 300 seconds when <= 0).
func VerifyWebhookSignature(rawBody []byte, signatureHeader string, signingSecret string, toleranceSeconds int64) bool {
	return verifyWebhookSignatureAt(rawBody, signatureHeader, signingSecret, toleranceSeconds, time.Now().Unix()) == nil
}

// ParseWebhookEvent verifies the webhook signature and unmarshals the JSON event envelope.
func ParseWebhookEvent(rawBody []byte, signatureHeader string, signingSecret string, toleranceSeconds int64) (*WebhookEvent, error) {
	return parseWebhookEventAt(rawBody, signatureHeader, signingSecret, toleranceSeconds, time.Now().Unix())
}

func parseWebhookEventAt(rawBody []byte, signatureHeader string, signingSecret string, toleranceSeconds int64, nowUnix int64) (*WebhookEvent, error) {
	if err := verifyWebhookSignatureAt(rawBody, signatureHeader, signingSecret, toleranceSeconds, nowUnix); err != nil {
		return nil, err
	}

	var event WebhookEvent
	if err := json.Unmarshal(rawBody, &event); err != nil {
		return nil, &WebhookSignatureError{
			Error: Error{
				Code:    "invalid_payload",
				Message: "Webhook payload is not valid JSON.",
				Status:  401,
			},
		}
	}
	if event.Type == "" || event.Data == nil {
		return nil, &WebhookSignatureError{
			Error: Error{
				Code:    "invalid_payload",
				Message: "Webhook payload must contain 'type' and 'data'.",
				Status:  401,
			},
		}
	}

	return &event, nil
}

func verifyWebhookSignatureAt(rawBody []byte, signatureHeader string, signingSecret string, toleranceSeconds int64, nowUnix int64) error {
	if signingSecret == "" {
		return &WebhookSignatureError{
			Error: Error{
				Code:    "missing_webhook_secret",
				Message: "signingSecret is required to verify Xelorra webhooks.",
				Status:  401,
			},
		}
	}

	trimmed := strings.TrimSpace(signatureHeader)
	if trimmed == "" {
		return &WebhookSignatureError{
			Error: Error{
				Code:    "missing_signature",
				Message: "Missing X-Xelorra-Signature header.",
				Status:  401,
			},
		}
	}

	if toleranceSeconds <= 0 {
		toleranceSeconds = DefaultWebhookToleranceSeconds
	}

	var rawTS string
	var signatures [][]byte

	for _, segment := range strings.Split(trimmed, ",") {
		part := strings.TrimSpace(segment)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return malformedSignatureErr()
		}
		k := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
		if v == "" {
			return malformedSignatureErr()
		}

		switch k {
		case "t":
			if rawTS != "" {
				return malformedSignatureErr()
			}
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return malformedSignatureErr()
			}
			rawTS = v
		case "v1":
			if len(v) != 64 {
				return malformedSignatureErr()
			}
			decoded, err := hex.DecodeString(v)
			if err != nil || len(decoded) != 32 {
				return malformedSignatureErr()
			}
			signatures = append(signatures, decoded)
		}
	}

	if rawTS == "" || len(signatures) == 0 {
		return malformedSignatureErr()
	}

	ts, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil || ts <= 0 {
		return malformedSignatureErr()
	}

	diff := nowUnix - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > toleranceSeconds {
		return &WebhookSignatureError{
			Error: Error{
				Code:    "expired_timestamp",
				Message: fmt.Sprintf("Webhook timestamp is outside the allowed %ds tolerance window.", toleranceSeconds),
				Status:  401,
			},
		}
	}

	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(rawTS))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	matched := false
	for _, sig := range signatures {
		if hmac.Equal(expected, sig) {
			matched = true
		}
	}

	if !matched {
		return &WebhookSignatureError{
			Error: Error{
				Code:    "invalid_signature",
				Message: "X-Xelorra-Signature verification failed.",
				Status:  401,
			},
		}
	}

	return nil
}

func malformedSignatureErr() error {
	return &WebhookSignatureError{
		Error: Error{
			Code:    "malformed_signature",
			Message: "X-Xelorra-Signature must follow 't=<unix_timestamp>,v1=<hmac_sha256_hex>'.",
			Status:  401,
		},
	}
}
