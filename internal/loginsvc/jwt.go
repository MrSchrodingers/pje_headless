// Package loginsvc implements session-reuse logic for the jus.br bearer token.
// It is independent of the transport (gRPC) and of the browser implementation,
// so the session-reuse behaviour is fully unit-testable via an injected loginFn.
package loginsvc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// parseBearerExp extracts the JWT expiry from a bearer string.
//
// It strips a leading "bearer " or "Bearer " scheme prefix (case-insensitive),
// then decodes the JWT payload (2nd dot-separated segment) using base64url
// encoding with no padding, and JSON-parses the "exp" field (unix seconds).
//
// Returns (time.Unix(exp, 0), true) on success.
// Returns (time.Time{}, false) on any failure: not a JWT, no exp field, exp==0,
// malformed base64, malformed JSON.  Never panics.
func parseBearerExp(bearer string) (time.Time, bool) {
	// Strip optional "bearer " / "Bearer " prefix.
	lower := strings.ToLower(bearer)
	if strings.HasPrefix(lower, "bearer ") {
		bearer = bearer[len("bearer "):]
	}
	bearer = strings.TrimSpace(bearer)

	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Exp == 0 {
		return time.Time{}, false
	}

	return time.Unix(claims.Exp, 0), true
}
