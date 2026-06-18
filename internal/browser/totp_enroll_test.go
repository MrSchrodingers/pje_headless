package browser

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// TestChooseTOTPSecretPrefersSpanAndNormalizes verifies the core extraction
// behavior of the CONFIGURE_TOTP enrollment step: the Keycloak page presents
// the base32 secret spaced inside #kc-totp-secret-key, and chooseTOTPSecret must
// return it normalized (whitespace stripped, uppercased) so it decodes as base32
// and feeds totpNow. The hidden #totpSecret value is only a fallback; when the
// span text is present it wins.
func TestChooseTOTPSecretPrefersSpanAndNormalizes(t *testing.T) {
	spanText := "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
	hidden := "IGNORED2SECRET22"

	got, err := chooseTOTPSecret(spanText, hidden)
	if err != nil {
		t.Fatalf("chooseTOTPSecret returned error: %v", err)
	}
	const want = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got != want {
		t.Fatalf("chooseTOTPSecret(span,hidden) = %q, want %q (span must win, normalized)", got, want)
	}

	// The returned secret must actually decode as base32 and drive totpNow,
	// proving it is usable end-to-end (not just a string match).
	if _, decErr := base32.StdEncoding.DecodeString(normalizeBase32Secret(got)); decErr != nil {
		t.Fatalf("chosen secret %q does not decode as base32: %v", got, decErr)
	}
	if _, totpErr := totpAt(got, time.Unix(59, 0)); totpErr != nil {
		t.Fatalf("chosen secret %q does not feed totpAt: %v", got, totpErr)
	}
}

// TestChooseTOTPSecretFallsBackToHidden verifies the documented fallback: when
// the visible span text is empty/whitespace, the hidden totpSecret input value
// is used instead, also normalized.
func TestChooseTOTPSecretFallsBackToHidden(t *testing.T) {
	got, err := chooseTOTPSecret("   \n\t  ", "gezd gnbv gy3t qojq")
	if err != nil {
		t.Fatalf("chooseTOTPSecret returned error: %v", err)
	}
	const want = "GEZDGNBVGY3TQOJQ"
	if got != want {
		t.Fatalf("chooseTOTPSecret(empty span, hidden) = %q, want %q", got, want)
	}
}

// TestChooseTOTPSecretBothEmptyFailsLoudly verifies the critical robustness
// requirement: on a CONFIGURE_TOTP page with no extractable secret, the function
// must fail with an error that names the selectors it tried, so the operator is
// not left guessing. Proceeding blind (returning "") is forbidden.
func TestChooseTOTPSecretBothEmptyFailsLoudly(t *testing.T) {
	_, err := chooseTOTPSecret("", "   ")
	if err == nil {
		t.Fatal("chooseTOTPSecret with no secret expected an error, got nil")
	}
	msg := err.Error()
	for _, sel := range []string{"#kc-totp-secret-key", "totpSecret"} {
		if !strings.Contains(msg, sel) {
			t.Fatalf("error %q must name the tried selector %q", msg, sel)
		}
	}
}

// TestTOTPEnrollWaitSelectorsOrder pins the priority order in which the enroll
// step waits for the secret element to exist before reading it. The Keycloak
// login-config-totp.ftl page renders the base32 secret in the visible span
// #kc-totp-secret-key; that span is the primary signal the DOM is ready and the
// secret is present, so it MUST be tried first. The hidden input
// ([name=totpSecret] / #totpSecret) is the documented fallback for page variants
// that omit the visible span, so it MUST come after. This order is the contract
// the wait/read logic follows; a regression that flips it would make the step
// wait on the wrong element and read before the secret span exists. The selectors
// must also be valid querySelector strings (the wait runs them via DOM.querySelector).
func TestTOTPEnrollWaitSelectorsOrder(t *testing.T) {
	sels := totpSecretWaitSelectors()
	if len(sels) < 2 {
		t.Fatalf("expected at least the span selector plus a hidden-input fallback, got %d: %v", len(sels), sels)
	}
	if sels[0] != "#kc-totp-secret-key" {
		t.Fatalf("first wait selector = %q, want the visible span #kc-totp-secret-key (primary readiness signal)", sels[0])
	}
	// Every later selector is a fallback and must reference the hidden totpSecret
	// input, not re-wait on the span.
	for _, s := range sels[1:] {
		if !strings.Contains(s, "totpSecret") {
			t.Fatalf("fallback wait selector %q must target the hidden totpSecret input", s)
		}
	}
	// The selectors are fed to DOM.querySelector verbatim; an empty or whitespace
	// selector would silently match nothing and stall the wait.
	for _, s := range sels {
		if strings.TrimSpace(s) == "" {
			t.Fatalf("wait selector %q is blank; DOM.querySelector would never match", s)
		}
	}
}
