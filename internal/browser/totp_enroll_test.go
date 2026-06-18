package browser

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// TestChooseTOTPSecretEncodesRawHidden pins the core Keycloak contract proven
// live on jus.br: the hidden totpSecret input holds the RAW shared key (a random
// a-zA-Z0-9 string), whose literal bytes ARE the HMAC key. chooseTOTPSecret must
// base32-ENCODE those bytes so the result feeds totpNow and matches the secret an
// authenticator app derives from the QR. The raw value observed live is used so
// the test reflects reality, not a synthetic happy path.
func TestChooseTOTPSecretEncodesRawHidden(t *testing.T) {
	const raw = "npdUoH6oyuJmmpJ6WrA7" // exact hidden totpSecret captured from jus.br

	got, err := chooseTOTPSecret("", raw)
	if err != nil {
		t.Fatalf("chooseTOTPSecret returned error: %v", err)
	}
	want := base32.StdEncoding.EncodeToString([]byte(raw))
	if got != want {
		t.Fatalf("chooseTOTPSecret(\"\", raw) = %q, want base32(raw) = %q", got, want)
	}

	// Decoding the result MUST yield the raw key bytes back: that is the exact
	// HMAC key Keycloak validates against (secret.getBytes()). A regression that
	// used the raw value directly, or normalized/uppercased it, would fail here.
	dec, decErr := base32.StdEncoding.DecodeString(normalizeBase32Secret(got))
	if decErr != nil {
		t.Fatalf("result %q does not decode as base32: %v", got, decErr)
	}
	if string(dec) != raw {
		t.Fatalf("decoded key = %q, want the raw secret bytes %q", string(dec), raw)
	}
	if _, totpErr := totpAt(got, time.Unix(59, 0)); totpErr != nil {
		t.Fatalf("result %q does not feed totpAt: %v", got, totpErr)
	}
}

// TestChooseTOTPSecretRawHiddenWinsOverSpan verifies that when BOTH candidates
// are present the hidden raw key wins and is base32-encoded, rather than the
// already-base32 span being returned verbatim. The span here is a valid but
// DIFFERENT base32 string, so returning it would be detectable.
func TestChooseTOTPSecretRawHiddenWinsOverSpan(t *testing.T) {
	const raw = "abcdefghij"             // raw key (10 bytes)
	const span = "GEZDGNBVGY3TQOJQ"      // valid base32 of "12345678", unrelated to raw

	got, err := chooseTOTPSecret(span, raw)
	if err != nil {
		t.Fatalf("chooseTOTPSecret returned error: %v", err)
	}
	want := base32.StdEncoding.EncodeToString([]byte(raw))
	if got != want {
		t.Fatalf("chooseTOTPSecret(span, raw) = %q, want base32(raw) = %q (hidden must win)", got, want)
	}
	if got == span {
		t.Fatalf("chooseTOTPSecret returned the span %q verbatim; the raw hidden key must take precedence", span)
	}
}

// TestChooseTOTPSecretFallsBackToValidBase32Span verifies the documented
// fallback: when the hidden field is absent, the visible span (already base32)
// is used as-is (normalized), NOT re-encoded.
func TestChooseTOTPSecretFallsBackToValidBase32Span(t *testing.T) {
	got, err := chooseTOTPSecret("gezd gnbv gy3t qojq", "   \n\t  ")
	if err != nil {
		t.Fatalf("chooseTOTPSecret returned error: %v", err)
	}
	const want = "GEZDGNBVGY3TQOJQ"
	if got != want {
		t.Fatalf("chooseTOTPSecret(span, empty hidden) = %q, want %q", got, want)
	}
}

// TestChooseTOTPSecretRejectsEmptyOrNonBase32Span verifies the critical
// robustness requirement: with no hidden key, a CONFIGURE_TOTP page whose span is
// empty OR not valid base32 must fail loudly (naming the sources tried) rather
// than enroll a blank or malformed code. The non-base32 case uses the exact
// value observed in the span on a live jus.br run.
func TestChooseTOTPSecretRejectsEmptyOrNonBase32Span(t *testing.T) {
	cases := map[string]string{
		"both empty":      "",
		"non-base32 span": "V97E67WAFAAWGC7VH8RX====", // contains 8/9, illegal base32
	}
	for name, span := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := chooseTOTPSecret(span, "   ")
			if err == nil {
				t.Fatalf("chooseTOTPSecret(%q, empty) expected an error, got nil", span)
			}
			msg := err.Error()
			for _, sel := range []string{"#kc-totp-secret-key", "totpSecret"} {
				if !strings.Contains(msg, sel) {
					t.Fatalf("error %q must name the tried source %q", msg, sel)
				}
			}
		})
	}
}

// TestTOTPEnrollWaitSelectorsOrder pins the priority order in which the enroll
// step waits for the secret element to exist before reading it. On jus.br the
// hidden totpSecret input is the authoritative, reliably-present source (it
// carries the raw key chooseTOTPSecret reads), while the visible span
// #kc-totp-secret-key was observed empty; so the hidden input MUST be tried
// first as the primary readiness signal and the span MUST come after as the
// fallback. A regression that flips this order would make the step wait up to the
// per-selector timeout on the possibly-empty span before falling through. The
// selectors must also be valid, non-blank querySelector strings (the wait runs
// them via DOM.querySelector).
func TestTOTPEnrollWaitSelectorsOrder(t *testing.T) {
	sels := totpSecretWaitSelectors()
	if len(sels) < 2 {
		t.Fatalf("expected the hidden-input selector plus a span fallback, got %d: %v", len(sels), sels)
	}
	if !strings.Contains(sels[0], "totpSecret") {
		t.Fatalf("first wait selector = %q, want the hidden totpSecret input (primary readiness signal)", sels[0])
	}
	// A later selector must cover the visible span fallback.
	foundSpan := false
	for _, s := range sels[1:] {
		if strings.Contains(s, "kc-totp-secret-key") {
			foundSpan = true
		}
	}
	if !foundSpan {
		t.Fatalf("wait selectors %v must include the #kc-totp-secret-key span as a fallback", sels)
	}
	// The selectors are fed to DOM.querySelector verbatim; an empty or whitespace
	// selector would silently match nothing and stall the wait.
	for _, s := range sels {
		if strings.TrimSpace(s) == "" {
			t.Fatalf("wait selector %q is blank; DOM.querySelector would never match", s)
		}
	}
}
