package signer_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// makePFX generates an ephemeral RSA-2048 key + self-signed cert, writes a PFX
// in t.TempDir() and returns (path, certDER). Never committed to the repo.
func makePFX(t *testing.T, password string) (pfxPath string, certDER []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pje-headless-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pfxData, err := pkcs12.Legacy.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("encode pfx: %v", err)
	}

	pfxPath = filepath.Join(t.TempDir(), "test.pfx")
	if err := os.WriteFile(pfxPath, pfxData, 0600); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	return pfxPath, certDER
}

// TestPFXSignVerifiesSHA256 verifies the observable behaviour:
// Sign produces a PKCS#1 v1.5 RSA signature over SHA-256(phrase) that
// is verifiable with the public key extracted from the PFX certificate.
func TestPFXSignVerifiesSHA256(t *testing.T) {
	pfxPath, certDER := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")

	if err := s.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	b64, err := s.Sign(context.Background(), "nonce-abc", "SHA256withRSA")
	if err != nil {
		t.Fatal(err)
	}

	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pub := cert.PublicKey.(*rsa.PublicKey)
	h := sha256.Sum256([]byte("nonce-abc"))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("assinatura nao verifica: %v", err)
	}
}

// TestPFXSignUnsupportedAlgorithm is a boundary case: an unknown algorithm
// must return an error, not a zero-value signature.
func TestPFXSignUnsupportedAlgorithm(t *testing.T) {
	pfxPath, _ := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")
	if err := s.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, err := s.Sign(context.Background(), "nonce-abc", "UNKNOWN")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm, got nil")
	}
}

// TestPFXLoginWrongPassword confirms that Login rejects an incorrect password.
func TestPFXLoginWrongPassword(t *testing.T) {
	pfxPath, _ := makePFX(t, "senha-correta")

	s := signer.NewPFXSigner(pfxPath, "senha-errada", "")
	if err := s.Login(context.Background()); err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}

// TestPFXAvailable asserts that Available returns true for a valid PFX
// and false when the file does not exist.
func TestPFXAvailable(t *testing.T) {
	pfxPath, _ := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")
	if !s.Available(context.Background()) {
		t.Fatal("expected Available=true for a valid PFX")
	}

	sMissing := signer.NewPFXSigner("/nonexistent/path.pfx", "senha", "")
	if sMissing.Available(context.Background()) {
		t.Fatal("expected Available=false for a missing file")
	}
}

// TestPFXIdentity verifies that Identity returns the correct Subject and
// NotAfter from the ephemeral certificate.
func TestPFXIdentity(t *testing.T) {
	pfxPath, _ := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")
	if err := s.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	id, err := s.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if id.Subject == "" {
		t.Error("expected non-empty Subject")
	}
	if id.NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
	// Self-signed certificate: Issuer must equal Subject.
	if id.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
	if id.Issuer != id.Subject {
		t.Errorf("self-signed: Issuer %q != Subject %q", id.Issuer, id.Subject)
	}
	if id.Serial == "" {
		t.Error("expected non-empty Serial")
	}
}

// TestPFXCertChainPKIPath verifies the observable behaviour of CertChainPKIPath:
// (a) the returned string is non-empty after Login; (b) decoding the base64 yields
// a valid ASN.1 SEQUENCE OF Certificate (RFC 3820 PKIPath) whose first element
// FullBytes equal the leaf certificate DER.
func TestPFXCertChainPKIPath(t *testing.T) {
	pfxPath, certDER := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")
	if err := s.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	b64, err := s.CertChainPKIPath(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b64 == "" {
		t.Fatal("expected non-empty CertChainPKIPath result")
	}

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		t.Fatalf("CertChainPKIPath: resultado nao e SEQUENCE OF valido: %v", err)
	}
	if len(seq) < 1 {
		t.Fatal("CertChainPKIPath: SEQUENCE vazia, esperado ao menos 1 certificado")
	}
	// Leaf must be the first element; FullBytes must equal the original DER.
	if !bytes.Equal(seq[0].FullBytes, certDER) {
		t.Fatal("CertChainPKIPath: primeiro elemento nao corresponde ao DER do certificado folha")
	}
}

// TestPFXConcurrentLoginSign exercises Login and Sign running in parallel to
// expose data races caught by the race detector (go test -race).
func TestPFXConcurrentLoginSign(t *testing.T) {
	pfxPath, _ := makePFX(t, "senha")

	s := signer.NewPFXSigner(pfxPath, "senha", "")
	// Warm-up: ensure Sign sees a non-nil key even if it races ahead of Login.
	if err := s.Login(context.Background()); err != nil {
		t.Fatal(err)
	}

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = s.Login(context.Background())
		}()
		go func() {
			defer wg.Done()
			_, _ = s.Sign(context.Background(), "nonce", "SHA256withRSA")
		}()
	}
	wg.Wait()
}
