package browser

import (
	"testing"
	"time"
)

// TestTOTPAt verifies the RFC 6238 (SHA1, 6-digit) generator against an
// independent oracle. The oracle values were computed with the Python stdlib
// reference (hmac/struct/hashlib), which is the same algorithm proven in
// production by vigia/services/pje_worker.py::get_totp_token. The t=59 case
// cross-checks the official RFC 6238 Appendix B vector (full value 94287082,
// truncated to 6 digits -> 287082), so the expectation is anchored to the
// standard, not to this package's own implementation.
func TestTOTPAt(t *testing.T) {
	const rfcSeedBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // ASCII "12345678901234567890"

	cases := []struct {
		name    string
		secret  string
		unixSec int64
		want    string
	}{
		{"rfc6238_appendixB_t59", rfcSeedBase32, 59, "287082"},
		{"rfc6238_t_1111111109", rfcSeedBase32, 1111111109, "081804"},
		{"rfc6238_t_1234567890", rfcSeedBase32, 1234567890, "005924"},
		{"rfc6238_t_2000000000", rfcSeedBase32, 2000000000, "279037"},
		// Lowercase secret must be accepted (case-folded).
		{"lowercase_secret", "jbswy3dpehpk3pxp", 59, "996554"},
		// Secret whose length is not a multiple of 8 must be padded.
		{"needs_padding_16", "GEZDGNBVGY3TQOJQ", 1234567890, "919219"},
		{"needs_padding_12", "GEZDGNBVGY3T", 1234567890, "334253"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := totpAt(tc.secret, time.Unix(tc.unixSec, 0))
			if err != nil {
				t.Fatalf("totpAt(%q, %d) returned error: %v", tc.secret, tc.unixSec, err)
			}
			if got != tc.want {
				t.Fatalf("totpAt(%q, %d) = %q, want %q", tc.secret, tc.unixSec, got, tc.want)
			}
			if len(got) != 6 {
				t.Fatalf("totpAt produced %d digits, want 6: %q", len(got), got)
			}
		})
	}
}

// TestTOTPAtSpacesNormalized verifies that whitespace inside the secret is
// stripped (banks often present the secret in spaced groups).
func TestTOTPAtSpacesNormalized(t *testing.T) {
	spaced := "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"
	tight := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	at := time.Unix(1234567890, 0)
	gotSpaced, err := totpAt(spaced, at)
	if err != nil {
		t.Fatalf("spaced secret returned error: %v", err)
	}
	gotTight, err := totpAt(tight, at)
	if err != nil {
		t.Fatalf("tight secret returned error: %v", err)
	}
	if gotSpaced != gotTight {
		t.Fatalf("spaced secret %q != tight secret %q", gotSpaced, gotTight)
	}
}

// TestTOTPAtEmptySecret verifies the error path: an empty secret cannot
// produce a valid OTP and must be rejected rather than silently returning "".
func TestTOTPAtEmptySecret(t *testing.T) {
	if _, err := totpAt("", time.Now()); err == nil {
		t.Fatal("totpAt(\"\") expected an error, got nil")
	}
}

// TestTOTPAtInvalidBase32 verifies the error path for a secret that is not
// valid base32 (contains characters outside the alphabet).
func TestTOTPAtInvalidBase32(t *testing.T) {
	if _, err := totpAt("0189!@#$", time.Now()); err == nil {
		t.Fatal("totpAt with invalid base32 expected an error, got nil")
	}
}
