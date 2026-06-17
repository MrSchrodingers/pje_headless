package signer

import (
	"context"
	"time"
)

// Identity holds identifying attributes of a certificate.
type Identity struct {
	Subject  string
	Issuer   string
	Serial   string
	NotAfter time.Time
}

// Signer abstracts asymmetric signing backed by a credential store (PFX, HSM, etc.).
type Signer interface {
	// Login loads and decodes the credential. Must be called before Sign.
	Login(ctx context.Context) error

	// Sign hashes phrase with algorithm and returns a base64-encoded PKCS#1 v1.5 signature.
	// Supported algorithms: MD5withRSA, SHA1withRSA, SHA256withRSA.
	Sign(ctx context.Context, phrase, algorithm string) (string, error)

	// CertChainPKIPath returns the ASN.1 PKIPath (SEQUENCE OF Certificate,
	// RFC 3820) of the certificate chain (leaf first), base64-encoded.
	CertChainPKIPath(ctx context.Context) (string, error)

	// Identity returns human-readable certificate metadata.
	Identity(ctx context.Context) (Identity, error)

	// Available reports whether the credential can be loaded and decoded
	// without side-effects (no state mutation).
	Available(ctx context.Context) bool
}
