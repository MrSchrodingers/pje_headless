package signer

import (
	"context"
	"crypto"
	"crypto/md5" // #nosec G501
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G501
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// PFXSigner implements Signer backed by a PKCS#12 (.pfx) file.
// Zero value is not usable; construct via NewPFXSigner.
// mu guards the mutable credential fields (key, cert, chain) so that
// Login (write) and Sign/Identity/CertChainPKIPath/Available (read) can
// run concurrently without data races.
type PFXSigner struct {
	path     string
	pass     string
	chainDir string

	mu    sync.RWMutex
	key   *rsa.PrivateKey
	cert  *x509.Certificate
	chain []*x509.Certificate
}

// NewPFXSigner creates a PFXSigner that reads the credential from path
// and decrypts it with pass. chainDir is reserved for external CA bundles
// and may be empty.
func NewPFXSigner(path, pass string, chainDir string) *PFXSigner {
	return &PFXSigner{
		path:     path,
		pass:     pass,
		chainDir: chainDir,
	}
}

// Login reads the PFX file, decodes it with the stored password, and retains
// the RSA private key, leaf certificate, and CA chain in memory.
func (s *PFXSigner) Login(_ context.Context) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("pfx login: read %q: %w", s.path, err)
	}

	pk, cert, chain, err := pkcs12.DecodeChain(data, s.pass)
	if err != nil {
		return fmt.Errorf("pfx login: decode: %w", err)
	}

	rsaKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return errors.New("pfx login: private key is not RSA")
	}

	s.mu.Lock()
	s.key = rsaKey
	s.cert = cert
	s.chain = chain
	s.mu.Unlock()
	return nil
}

// Sign hashes phrase with the requested algorithm and returns a base64-encoded
// PKCS#1 v1.5 RSA signature. Login must be called first.
func (s *PFXSigner) Sign(_ context.Context, phrase, algorithm string) (string, error) {
	s.mu.RLock()
	key := s.key
	s.mu.RUnlock()

	if key == nil {
		return "", errors.New("pfx sign: not logged in")
	}

	h, cryptoHash, err := digest(algorithm, []byte(phrase))
	if err != nil {
		return "", err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash, h)
	if err != nil {
		return "", fmt.Errorf("pfx sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// CertChainPKIPath returns the ASN.1 PKIPath (SEQUENCE OF Certificate, RFC 3820)
// of the certificate chain (leaf first), base64-encoded.
// Login must be called first.
func (s *PFXSigner) CertChainPKIPath(_ context.Context) (string, error) {
	s.mu.RLock()
	cert := s.cert
	chain := s.chain
	s.mu.RUnlock()

	if cert == nil {
		return "", errors.New("pfx chain: not logged in")
	}

	extraDER := make([][]byte, len(chain))
	for i, c := range chain {
		extraDER[i] = c.Raw
	}

	return PKIPathB64(cert.Raw, extraDER)
}

// Identity returns Subject, Issuer, Serial and NotAfter from the leaf cert.
// Login must be called first.
func (s *PFXSigner) Identity(_ context.Context) (Identity, error) {
	s.mu.RLock()
	cert := s.cert
	s.mu.RUnlock()

	if cert == nil {
		return Identity{}, errors.New("pfx identity: not logged in")
	}

	return Identity{
		Subject:  cert.Subject.String(),
		Issuer:   cert.Issuer.String(),
		Serial:   cert.SerialNumber.String(),
		NotAfter: cert.NotAfter,
	}, nil
}

// Available probes the PFX without mutating the receiver. Returns true only
// when the file exists and can be decoded with the stored password.
func (s *PFXSigner) Available(_ context.Context) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return false
	}
	_, _, _, err = pkcs12.DecodeChain(data, s.pass)
	return err == nil
}

// digest hashes data with the algorithm encoded as a Java-style OID name and
// returns (hashBytes, crypto.Hash, error). Supported: MD5withRSA, SHA1withRSA,
// SHA256withRSA. This helper is shared across signer implementations.
func digest(algorithm string, data []byte) ([]byte, crypto.Hash, error) {
	switch algorithm {
	case "MD5withRSA":
		h := md5.Sum(data) // #nosec G401
		return h[:], crypto.MD5, nil
	case "SHA1withRSA":
		h := sha1.Sum(data) // #nosec G401 -- SHA1 retained for legacy PJe compatibility only.
		return h[:], crypto.SHA1, nil
	case "SHA256withRSA":
		h := sha256.Sum256(data)
		return h[:], crypto.SHA256, nil
	default:
		return nil, 0, fmt.Errorf("pfx digest: unsupported algorithm %q", algorithm)
	}
}
