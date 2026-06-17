package signer_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// selfSignedDER generates an ephemeral self-signed RSA-2048 certificate and
// returns it in DER encoding. The certificate is not written to disk.
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pje-pkipath-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// TestPKIPathRoundTrip verifica que PKIPathB64 produz um ASN.1 SEQUENCE OF
// Certificate valido (RFC 3820) e que o primeiro elemento decodificado bate
// com o DER original da folha.
func TestPKIPathRoundTrip(t *testing.T) {
	leaf := selfSignedDER(t)

	b64, err := signer.PKIPathB64(leaf, nil)
	if err != nil {
		t.Fatal(err)
	}

	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("nao e SEQUENCE OF: %v", err)
	}
	if len(seq) != 1 {
		t.Fatalf("esperado 1 cert, got %d", len(seq))
	}
	if !bytes.Equal(seq[0].FullBytes, leaf) {
		t.Fatal("FullBytes do primeiro elemento nao corresponde ao DER da folha")
	}
}

// TestPKIPathMultipleCerts verifica o caso de borda com N > 1 certificados:
// a cadeia preserva a ordem (folha primeiro) e todos os elementos sao
// recuperaveis apos decodificacao.
func TestPKIPathMultipleCerts(t *testing.T) {
	leaf := selfSignedDER(t)
	ca1 := selfSignedDER(t)
	ca2 := selfSignedDER(t)

	b64, err := signer.PKIPathB64(leaf, [][]byte{ca1, ca2})
	if err != nil {
		t.Fatal(err)
	}

	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		t.Fatalf("nao e SEQUENCE OF: %v", err)
	}
	if len(seq) != 3 {
		t.Fatalf("esperado 3 certs, got %d", len(seq))
	}
	if !bytes.Equal(seq[0].FullBytes, leaf) {
		t.Fatal("elemento 0 nao e a folha")
	}
	if !bytes.Equal(seq[1].FullBytes, ca1) {
		t.Fatal("elemento 1 nao e ca1")
	}
	if !bytes.Equal(seq[2].FullBytes, ca2) {
		t.Fatal("elemento 2 nao e ca2")
	}
}

// TestPKIPathEmptyLeaf verifica que PKIPathB64 retorna erro quando leafDER
// e vazio (caso de borda de entrada invalida).
func TestPKIPathEmptyLeaf(t *testing.T) {
	_, err := signer.PKIPathB64(nil, nil)
	if err == nil {
		t.Fatal("esperado erro para leafDER vazio, got nil")
	}
}
