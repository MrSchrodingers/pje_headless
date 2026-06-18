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
