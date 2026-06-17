package signer

import (
	"context"
	"crypto/md5" // #nosec G401
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	p11 "github.com/miekg/pkcs11"
)

// md5DigestInfoPrefix is the fixed DER header for an MD5 DigestInfo structure
// (RFC 3447, Appendix B.1):
//
//	SEQUENCE (32) {
//	  SEQUENCE (12) {
//	    OID 1.2.840.113549.2.5   (md5)
//	    NULL
//	  }
//	  OCTET STRING (16)          <- MD5 hash follows
//	}
//
// The token's CKM_RSA_PKCS mechanism signs a pre-formatted DigestInfo blob
// without computing any hash internally, so we must supply the full structure.
var md5DigestInfoPrefix = []byte{
	0x30, 0x20, // SEQUENCE, length 32
	0x30, 0x0c, // SEQUENCE, length 12 (AlgorithmIdentifier)
	0x06, 0x08, // OID, length 8
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, // 1.2.840.113549.2.5 (md5)
	0x05, 0x00, // NULL
	0x04, 0x10, // OCTET STRING, length 16 (MD5 hash)
}

// PKCS11Signer implements Signer backed by a PKCS#11 hardware token (e.g. SafeSign A3).
// The RSA private key never leaves the hardware; all signing operations run inside
// the token via C_Sign / C_SignInit. Construct via NewPKCS11Signer.
//
// mu serialises every token operation. A single PKCS#11 session is kept open after
// Login; the token is not thread-safe for concurrent C_Sign calls on the same session.
type PKCS11Signer struct {
	module   string // path to the PKCS#11 shared library
	pin      string // user PIN
	slotHint string // optional: decimal index into GetSlotList result
	label    string // optional: token label; preferred over slotHint when non-empty
	chainDir string // reserved for external CA bundles; may be empty

	mu      sync.Mutex
	p       *p11.Ctx
	sh      p11.SessionHandle
	privKey p11.ObjectHandle
	leafDER []byte // DER-encoded leaf certificate (CKA_VALUE of CKO_CERTIFICATE)
}

// NewPKCS11Signer returns a PKCS11Signer bound to the given module and credentials.
// Login must be called before Sign.
//
//   - module:   absolute path to the PKCS#11 .so (e.g. /usr/lib/libaetpkss.so).
//   - pin:      token user PIN.
//   - slotHint: decimal index (0-based) in the slot list to use when label is "".
//   - label:    token label string; when non-empty it takes precedence over slotHint.
//   - chainDir: reserved for future CA bundle support; pass "" to ignore.
func NewPKCS11Signer(module, pin, slotHint, label, chainDir string) *PKCS11Signer {
	return &PKCS11Signer{
		module:   module,
		pin:      pin,
		slotHint: slotHint,
		label:    label,
		chainDir: chainDir,
	}
}

// Login initialises the PKCS#11 module, opens a read-write session on the target
// slot, authenticates with the user PIN, and locates the CKO_PRIVATE_KEY and
// CKO_CERTIFICATE objects. It stores the certificate DER for later use by Identity
// and CertChainPKIPath.
//
// Login is idempotent: if a session is already open it is torn down and re-opened.
func (s *PKCS11Signer) Login(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.teardown()

	ctx := p11.New(s.module)
	if ctx == nil {
		return fmt.Errorf("pkcs11 login: cannot load module %q", s.module)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: Initialize: %w", err)
	}

	slotID, err := findSlot(ctx, s.label, s.slotHint)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: %w", err)
	}

	sh, err := ctx.OpenSession(slotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: OpenSession slot %d: %w", slotID, err)
	}

	if err := ctx.Login(sh, p11.CKU_USER, s.pin); err != nil {
		if !alreadyLoggedIn(err) {
			_ = ctx.CloseSession(sh)
			_ = ctx.Finalize()
			ctx.Destroy()
			return fmt.Errorf("pkcs11 login: C_Login: %w", err)
		}
		// token already authenticated on this module — treat as success
	}

	privKey, err := findObject(ctx, sh, p11.CKO_PRIVATE_KEY)
	if err != nil {
		_ = ctx.CloseSession(sh)
		_ = ctx.Finalize()
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: find private key: %w", err)
	}

	certHandle, err := findObject(ctx, sh, p11.CKO_CERTIFICATE)
	if err != nil {
		_ = ctx.CloseSession(sh)
		_ = ctx.Finalize()
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: find certificate: %w", err)
	}

	attrs, err := ctx.GetAttributeValue(sh, certHandle, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_VALUE, nil),
	})
	if err != nil {
		_ = ctx.CloseSession(sh)
		_ = ctx.Finalize()
		ctx.Destroy()
		return fmt.Errorf("pkcs11 login: GetAttributeValue(CKA_VALUE): %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		_ = ctx.CloseSession(sh)
		_ = ctx.Finalize()
		ctx.Destroy()
		return errors.New("pkcs11 login: certificate DER is empty")
	}

	// Commit state only after all operations succeed.
	s.p = ctx
	s.sh = sh
	s.privKey = privKey
	s.leafDER = attrs[0].Value
	return nil
}

// teardown closes the open session and finalises the module. Must be called with mu held.
func (s *PKCS11Signer) teardown() {
	if s.p == nil {
		return
	}
	_ = s.p.CloseSession(s.sh)
	_ = s.p.Finalize()
	s.p.Destroy()
	s.p = nil
	s.sh = 0
	s.privKey = 0
	s.leafDER = nil
}

// Sign hashes phrase with the requested algorithm and returns a base64-encoded
// PKCS#1 v1.5 RSA signature produced entirely inside the hardware token.
//
// Mechanism mapping (de-risked via PyKCS11 on the target SafeSign token):
//   - SHA256withRSA -> CKM_SHA256_RSA_PKCS (combined hash-and-sign)
//   - SHA1withRSA   -> CKM_SHA1_RSA_PKCS   (combined hash-and-sign)
//   - MD5withRSA    -> CKM_RSA_PKCS        (raw; caller supplies full DigestInfo)
//
// Token access is serialised with mu; C_SignInit / C_Sign must run atomically on
// the same session.
func (s *PKCS11Signer) Sign(_ context.Context, phrase, algorithm string) (string, error) {
	mechID, needsDigestInfo, err := algorithmToMechanism(algorithm)
	if err != nil {
		return "", err
	}

	var data []byte
	if needsDigestInfo {
		data = md5DigestInfo([]byte(phrase))
	} else {
		data = []byte(phrase)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.p == nil {
		return "", errors.New("pkcs11 sign: not logged in")
	}

	mech := []*p11.Mechanism{p11.NewMechanism(mechID, nil)}
	if err := s.p.SignInit(s.sh, mech, s.privKey); err != nil {
		return "", fmt.Errorf("pkcs11 sign: SignInit: %w", err)
	}

	sig, err := s.p.Sign(s.sh, data)
	if err != nil {
		return "", fmt.Errorf("pkcs11 sign: Sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

// CertChainPKIPath returns the ASN.1 PKIPath (SEQUENCE OF Certificate, RFC 3820)
// base64-encoded, containing only the leaf certificate read from the token.
// Login must be called first.
func (s *PKCS11Signer) CertChainPKIPath(_ context.Context) (string, error) {
	s.mu.Lock()
	der := s.leafDER
	s.mu.Unlock()

	if der == nil {
		return "", errors.New("pkcs11 chain: not logged in")
	}

	return PKIPathB64(der, nil)
}

// Identity parses the token's leaf certificate and returns Subject, Issuer,
// Serial, and NotAfter. Login must be called first.
func (s *PKCS11Signer) Identity(_ context.Context) (Identity, error) {
	s.mu.Lock()
	der := s.leafDER
	s.mu.Unlock()

	if der == nil {
		return Identity{}, errors.New("pkcs11 identity: not logged in")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Identity{}, fmt.Errorf("pkcs11 identity: parse cert: %w", err)
	}

	return Identity{
		Subject:  cert.Subject.String(),
		Issuer:   cert.Issuer.String(),
		Serial:   cert.SerialNumber.String(),
		NotAfter: cert.NotAfter,
	}, nil
}

// Available reports whether the PKCS#11 module can be loaded and at least one
// slot with a token is present (and, if label is set, a slot bearing that label
// exists). It does not mutate receiver state and does not require prior Login.
func (s *PKCS11Signer) Available(_ context.Context) bool {
	ctx := p11.New(s.module)
	if ctx == nil {
		return false
	}
	defer ctx.Destroy()

	if err := ctx.Initialize(); err != nil {
		return false
	}
	defer func() { _ = ctx.Finalize() }()

	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		return false
	}

	if s.label == "" {
		return true
	}

	for _, slotID := range slots {
		info, err := ctx.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		if strings.TrimRight(info.Label, " ") == strings.TrimRight(s.label, " ") {
			return true
		}
	}
	return false
}

// --- package-level helpers (tested directly from pkcs11_test.go) ---------------

// algorithmToMechanism maps a Java-style algorithm name to the PKCS#11 mechanism
// constant and whether the caller must pre-build a DigestInfo wrapper.
//
// Supported mappings (verified on SafeSign SafeNet token via PyKCS11):
//   - SHA256withRSA -> CKM_SHA256_RSA_PKCS, no DigestInfo
//   - SHA1withRSA   -> CKM_SHA1_RSA_PKCS,   no DigestInfo
//   - MD5withRSA    -> CKM_RSA_PKCS,         DigestInfo required
func algorithmToMechanism(algorithm string) (mech uint, needsDigestInfo bool, err error) {
	switch algorithm {
	case "SHA256withRSA":
		return p11.CKM_SHA256_RSA_PKCS, false, nil
	case "SHA1withRSA":
		return p11.CKM_SHA1_RSA_PKCS, false, nil
	case "MD5withRSA":
		return p11.CKM_RSA_PKCS, true, nil
	default:
		return 0, false, fmt.Errorf("pkcs11: unsupported algorithm %q", algorithm)
	}
}

// md5DigestInfo returns the DER-encoded DigestInfo structure for MD5 as required
// by PKCS#1 v1.5 / CKM_RSA_PKCS raw signing:
//
//	DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
//
// The result is always 34 bytes: 18-byte prefix || md5(data).
func md5DigestInfo(data []byte) []byte {
	h := md5.Sum(data) // #nosec G401
	out := make([]byte, len(md5DigestInfoPrefix)+len(h))
	copy(out, md5DigestInfoPrefix)
	copy(out[len(md5DigestInfoPrefix):], h[:])
	return out
}

// findSlot returns the slot ID matching label (trimmed) when non-empty,
// otherwise uses slotHint as a decimal index into the slot list, defaulting
// to the first available slot.
func findSlot(ctx *p11.Ctx, label, slotHint string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("GetSlotList: %w", err)
	}
	if len(slots) == 0 {
		return 0, errors.New("no slots with token present")
	}

	if label != "" {
		want := strings.TrimRight(label, " ")
		for _, slotID := range slots {
			info, err := ctx.GetTokenInfo(slotID)
			if err != nil {
				continue
			}
			if strings.TrimRight(info.Label, " ") == want {
				return slotID, nil
			}
		}
		return 0, fmt.Errorf("no slot found with token label %q", label)
	}

	if slotHint != "" {
		var idx int
		if _, err := fmt.Sscanf(slotHint, "%d", &idx); err == nil && idx >= 0 && idx < len(slots) {
			return slots[idx], nil
		}
	}

	return slots[0], nil
}

// alreadyLoggedIn reports whether err is CKR_USER_ALREADY_LOGGED_IN (0x100).
// When C_Login returns this code the token already has an authenticated session
// (the module maintains per-token login state across sessions/instances), so
// Login should treat it as success rather than propagating an error.
func alreadyLoggedIn(err error) bool {
	e, ok := err.(p11.Error)
	return ok && e == p11.CKR_USER_ALREADY_LOGGED_IN
}

// findObject locates the first PKCS#11 object of the given class
// (CKO_PRIVATE_KEY or CKO_CERTIFICATE) in the open session.
func findObject(ctx *p11.Ctx, sh p11.SessionHandle, class uint) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, class),
	}
	if err := ctx.FindObjectsInit(sh, template); err != nil {
		return 0, fmt.Errorf("FindObjectsInit class=0x%x: %w", class, err)
	}

	objs, _, err := ctx.FindObjects(sh, 16)
	if finErr := ctx.FindObjectsFinal(sh); finErr != nil && err == nil {
		err = finErr
	}
	if err != nil {
		return 0, fmt.Errorf("FindObjects class=0x%x: %w", class, err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("no object of class 0x%x found in token", class)
	}
	return objs[0], nil
}
