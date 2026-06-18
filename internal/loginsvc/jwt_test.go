package loginsvc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// buildJWT constructs a minimal JWT with the given exp claim for test purposes.
// It does not sign - parseBearerExp only decodes the payload; the signature is
// not verified (the manager trusts its own cached token, not an arbitrary one).
func buildJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{"sub": "test", "exp": exp})
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadEnc + "." + sig
}

// TestParseBearerExp_ValidJWT verifies that a correctly formed JWT with an exp
// claim is parsed and the expiry matches the encoded unix timestamp.
func TestParseBearerExp_ValidJWT(t *testing.T) {
	expUnix := time.Now().Add(10 * time.Minute).Unix()
	bearer := buildJWT(expUnix)

	got, ok := parseBearerExp(bearer)
	if !ok {
		t.Fatal("parseBearerExp returned ok=false for valid JWT")
	}
	if got.Unix() != expUnix {
		t.Errorf("exp: got %d, want %d", got.Unix(), expUnix)
	}
}

// TestParseBearerExp_BearerPrefix verifies that "bearer " and "Bearer " scheme
// prefixes (case-insensitive) are stripped before parsing.
func TestParseBearerExp_BearerPrefix(t *testing.T) {
	expUnix := time.Now().Add(5 * time.Minute).Unix()
	raw := buildJWT(expUnix)

	for _, prefix := range []string{"bearer ", "Bearer "} {
		t.Run(prefix, func(t *testing.T) {
			got, ok := parseBearerExp(prefix + raw)
			if !ok {
				t.Fatalf("parseBearerExp(%q+jwt) returned ok=false", prefix)
			}
			if got.Unix() != expUnix {
				t.Errorf("exp: got %d, want %d", got.Unix(), expUnix)
			}
		})
	}
}

// TestParseBearerExp_NoExp verifies that a JWT without an exp claim returns ok=false.
func TestParseBearerExp_NoExp(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	bearer := header + "." + payload + "." + sig

	_, ok := parseBearerExp(bearer)
	if ok {
		t.Error("parseBearerExp returned ok=true for JWT without exp")
	}
}

// TestParseBearerExp_NonJWT verifies that a plain string (not a JWT) returns ok=false.
func TestParseBearerExp_NonJWT(t *testing.T) {
	_, ok := parseBearerExp("not-a-jwt-at-all")
	if ok {
		t.Error("parseBearerExp returned ok=true for non-JWT input")
	}
}

// TestParseBearerExp_MalformedPayload verifies that a JWT with non-base64url payload
// returns ok=false without panicking.
func TestParseBearerExp_MalformedPayload(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	malformed := header + ".!!!notbase64!!!.sig"

	_, ok := parseBearerExp(malformed)
	if ok {
		t.Error("parseBearerExp returned ok=true for malformed payload")
	}
}

// TestParseBearerExp_GarbageNoPanic verifies that completely random garbage
// input never causes a panic.
func TestParseBearerExp_GarbageNoPanic(t *testing.T) {
	inputs := []string{
		"",
		".",
		"..",
		"a.b",
		strings.Repeat("x", 10000),
		"\x00\xFF\xFE",
		"bearer ",
		"Bearer ",
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseBearerExp panicked on input %q: %v", in, r)
				}
			}()
			parseBearerExp(in)
		}()
	}
}

// TestParseBearerExp_ExpZeroReturnsFalse verifies that exp=0 in a JWT returns
// ok=false (zero is treated as missing/unset, per spec semantics).
func TestParseBearerExp_ExpZeroReturnsFalse(t *testing.T) {
	bearer := buildJWT(0)
	_, ok := parseBearerExp(bearer)
	if ok {
		t.Error("parseBearerExp returned ok=true for exp=0 (should be treated as absent)")
	}
}
