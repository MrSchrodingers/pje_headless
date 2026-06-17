package browser

import (
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 mandates HMAC-SHA1 for TOTP.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// totpStep is the RFC 6238 time step in seconds.
const totpStep = 30

// totpAt computes the RFC 6238 TOTP (HMAC-SHA1, 6 digits) for the given base32
// secret at instant at. It is a faithful port of the algorithm proven in
// production by vigia/services/pje_worker.py::get_totp_token, with one
// deliberate contract change: an invalid or empty secret returns an error
// instead of silently yielding "". A silent empty code would let the 2FA flow
// submit a blank OTP and fail opaquely; failing loudly is the documented
// requirement.
//
// The secret is upper-cased, stripped of all whitespace, and right-padded with
// '=' to a multiple of 8 characters before base32 decoding.
func totpAt(secret string, at time.Time) (string, error) {
	normalized := normalizeBase32Secret(secret)
	if normalized == "" {
		return "", fmt.Errorf("totp: empty secret")
	}

	key, err := base32.StdEncoding.DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("totp: invalid base32 secret: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("totp: secret decoded to zero bytes")
	}

	counter := uint64(at.Unix()) / totpStep //nolint:gosec // Unix() is non-negative for any realistic clock.
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	code := truncated % 1_000_000

	return fmt.Sprintf("%06d", code), nil
}

// totpNow computes the current TOTP for secret using the wall clock.
func totpNow(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// normalizeBase32Secret upper-cases the secret, removes all whitespace, and
// right-pads with '=' so the length is a multiple of 8 (base32 block size).
func normalizeBase32Secret(secret string) string {
	var b strings.Builder
	b.Grow(len(secret))
	for _, r := range secret {
		switch r {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	s := strings.ToUpper(b.String())
	if s == "" {
		return ""
	}
	if rem := len(s) % 8; rem != 0 {
		s += strings.Repeat("=", 8-rem)
	}
	return s
}
