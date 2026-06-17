package signer

// Unit tests for PKCS11Signer pure helpers.
// These run without any hardware token and must pass with:
//   go test ./internal/signer/
//
// E2e tests that require a real token live in pkcs11_e2e_test.go (build tag: token).

import (
	"crypto/md5" // #nosec G401
	"encoding/asn1"
	"errors"
	"testing"

	p11 "github.com/miekg/pkcs11"
)

// TestAlgorithmToMechanism verifies the observable mapping from Java-style
// algorithm name to PKCS#11 mechanism constant and the DigestInfo flag.
func TestAlgorithmToMechanism(t *testing.T) {
	cases := []struct {
		algorithm      string
		wantMech       uint
		wantDigestInfo bool
		wantErr        bool
	}{
		{"SHA256withRSA", p11.CKM_SHA256_RSA_PKCS, false, false},
		{"SHA1withRSA", p11.CKM_SHA1_RSA_PKCS, false, false},
		{"MD5withRSA", p11.CKM_RSA_PKCS, true, false},
		{"UNKNOWN", 0, false, true},
		{"", 0, false, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.algorithm, func(t *testing.T) {
			mech, needsDigestInfo, err := algorithmToMechanism(tc.algorithm)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("algorithm %q: expected error, got nil", tc.algorithm)
				}
				return
			}
			if err != nil {
				t.Fatalf("algorithm %q: unexpected error: %v", tc.algorithm, err)
			}
			if mech != tc.wantMech {
				t.Errorf("algorithm %q: mechanism = 0x%x, want 0x%x", tc.algorithm, mech, tc.wantMech)
			}
			if needsDigestInfo != tc.wantDigestInfo {
				t.Errorf("algorithm %q: needsDigestInfo = %v, want %v", tc.algorithm, needsDigestInfo, tc.wantDigestInfo)
			}
		})
	}
}

// TestMD5DigestInfoStructure verifies that md5DigestInfo produces a valid
// ASN.1 DigestInfo structure for MD5, as required for CKM_RSA_PKCS raw signing.
// Concretely it checks:
//  1. Output length is 18-byte header + 16-byte MD5 hash = 34 bytes.
//  2. The first 18 bytes match the known DER prefix for MD5 AlgorithmIdentifier.
//  3. The last 16 bytes equal the MD5 digest of the input.
//  4. The whole blob parses as a valid ASN.1 SEQUENCE with two elements
//     (AlgorithmIdentifier and digest OCTET STRING).
func TestMD5DigestInfoStructure(t *testing.T) {
	input := []byte("nonce-test-md5")
	out := md5DigestInfo(input)

	const wantLen = 34 // 18-byte prefix + 16-byte MD5
	if len(out) != wantLen {
		t.Fatalf("md5DigestInfo length = %d, want %d", len(out), wantLen)
	}

	// Verify known DER prefix for MD5 DigestInfo.
	wantPrefix := []byte{
		0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
		0x05, 0x00, 0x04, 0x10,
	}
	for i, b := range wantPrefix {
		if out[i] != b {
			t.Errorf("prefix byte[%d] = 0x%02x, want 0x%02x", i, out[i], b)
		}
	}

	// Verify the hash portion is indeed MD5(input).
	wantHash := md5.Sum(input) // #nosec G401
	for i, b := range wantHash {
		if out[18+i] != b {
			t.Errorf("hash byte[%d] = 0x%02x, want 0x%02x", i, out[18+i], b)
		}
	}

	// Verify the whole structure is parseable as ASN.1 SEQUENCE { SEQUENCE, OCTET STRING }.
	var outer struct {
		AlgID  asn1.RawValue
		Digest []byte
	}
	rest, err := asn1.Unmarshal(out, &outer)
	if err != nil {
		t.Fatalf("asn1.Unmarshal DigestInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("asn1.Unmarshal: unexpected trailing bytes: %x", rest)
	}
}

// TestMD5DigestInfoEdgeCases verifies that md5DigestInfo handles empty input
// without panicking and still produces a 34-byte valid structure.
func TestMD5DigestInfoEdgeCases(t *testing.T) {
	out := md5DigestInfo([]byte{})
	if len(out) != 34 {
		t.Fatalf("empty input: length = %d, want 34", len(out))
	}

	wantHash := md5.Sum([]byte{}) // #nosec G401
	for i, b := range wantHash {
		if out[18+i] != b {
			t.Errorf("empty input hash byte[%d] = 0x%02x, want 0x%02x", i, out[18+i], b)
		}
	}
}

// TestAlreadyLoggedIn verifies the observable behaviour of alreadyLoggedIn:
// the function must classify CKR_USER_ALREADY_LOGGED_IN as "already logged in"
// (return true) and must NOT classify any other error code or non-pkcs11 error
// that way (return false).
//
// This covers the Login idempotency fix: when C_Login returns 0x100 the caller
// must treat the session as authenticated rather than propagating an error.
func TestAlreadyLoggedIn(t *testing.T) {
	t.Run("CKR_USER_ALREADY_LOGGED_IN is treated as success", func(t *testing.T) {
		err := p11.Error(p11.CKR_USER_ALREADY_LOGGED_IN) // 0x100
		if !alreadyLoggedIn(err) {
			t.Fatalf("alreadyLoggedIn(%v) = false; want true for CKR_USER_ALREADY_LOGGED_IN", err)
		}
	})

	t.Run("different pkcs11 error code is not treated as success", func(t *testing.T) {
		err := p11.Error(p11.CKR_PIN_INCORRECT)
		if alreadyLoggedIn(err) {
			t.Fatalf("alreadyLoggedIn(%v) = true; want false for CKR_PIN_INCORRECT", err)
		}
	})

	t.Run("non-pkcs11 error is not treated as success", func(t *testing.T) {
		err := errors.New("some unrelated error")
		if alreadyLoggedIn(err) {
			t.Fatalf("alreadyLoggedIn(%v) = true; want false for a plain error", err)
		}
	})
}
