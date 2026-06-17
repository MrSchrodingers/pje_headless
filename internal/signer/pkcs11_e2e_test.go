//go:build token

package signer

// E2e tests that require a real PKCS#11 token (SafeSign / SafeNet A3).
// Run in srvtoken with:
//   PJE_PKCS11_MODULE=/usr/lib/libaetpkss.so PJE_PKCS11_PIN=<pin> \
//     go test -tags token ./internal/signer/ -v -run TestPKCS11
//
// These tests are skipped automatically when the env vars are absent,
// so `go test ./internal/signer/` (without -tags token) never reaches them.

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"
)

// TestPKCS11SignOnRealTokenSHA256 is the canonical end-to-end validation:
// it signs a nonce with SHA256withRSA inside the hardware token and verifies
// the signature against the public key extracted from the token's own certificate.
// This mirrors the PyKCS11 proof-of-concept that returned VERIFY OK.
func TestPKCS11SignOnRealTokenSHA256(t *testing.T) {
	mod := os.Getenv("PJE_PKCS11_MODULE")
	pin := os.Getenv("PJE_PKCS11_PIN")
	if mod == "" || pin == "" {
		t.Skip("sem token configurado: defina PJE_PKCS11_MODULE e PJE_PKCS11_PIN")
	}

	s := NewPKCS11Signer(mod, pin, "", "", "")

	if err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	const phrase = "nonce-go-e2e"
	b64, err := s.Sign(context.Background(), phrase, "SHA256withRSA")
	if err != nil {
		t.Fatalf("Sign SHA256withRSA: %v", err)
	}

	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode signature: %v", err)
	}

	// Verify against the public key of the certificate read from the token.
	cert, err := x509.ParseCertificate(s.leafDER)
	if err != nil {
		t.Fatalf("parse token certificate: %v", err)
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("token certificate public key is not RSA")
	}

	h := sha256.Sum256([]byte(phrase))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("VERIFY FAIL: %v", err)
	}

	id, err := s.Identity(context.Background())
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	t.Logf("assinou como: %s", id.Subject)
	t.Logf("valido ate: %s", id.NotAfter)
	t.Log("VERIFY OK")
}

// TestPKCS11CertChainPKIPath verifies that CertChainPKIPath returns a
// non-empty base64 string after a successful Login.
func TestPKCS11CertChainPKIPath(t *testing.T) {
	mod := os.Getenv("PJE_PKCS11_MODULE")
	pin := os.Getenv("PJE_PKCS11_PIN")
	if mod == "" || pin == "" {
		t.Skip("sem token configurado")
	}

	s := NewPKCS11Signer(mod, pin, "", "", "")
	if err := s.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	b64, err := s.CertChainPKIPath(context.Background())
	if err != nil {
		t.Fatalf("CertChainPKIPath: %v", err)
	}
	if b64 == "" {
		t.Fatal("CertChainPKIPath: returned empty string")
	}
	t.Logf("PKIPath length (base64): %d chars", len(b64))
}

// TestPKCS11Available verifies that Available returns true when the module
// and token are present.
func TestPKCS11Available(t *testing.T) {
	mod := os.Getenv("PJE_PKCS11_MODULE")
	pin := os.Getenv("PJE_PKCS11_PIN")
	if mod == "" || pin == "" {
		t.Skip("sem token configurado")
	}

	s := NewPKCS11Signer(mod, pin, "", "", "")
	if !s.Available(context.Background()) {
		t.Fatal("Available returned false with a connected token")
	}

	sMissing := NewPKCS11Signer("/nonexistent/lib.so", pin, "", "", "")
	if sMissing.Available(context.Background()) {
		t.Fatal("Available returned true for a nonexistent module")
	}
}
