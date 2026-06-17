package signer

import (
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
)

// PKIPathB64 serializes a certificate chain as an ASN.1 SEQUENCE OF Certificate
// (RFC 3820, section 4.2 — PKIPath), leaf first, and returns the result
// base64 (StdEncoding) encoded.
//
// leafDER must be the DER-encoded leaf certificate (non-empty). extraDER
// contains intermediate and root CA certificates in chain order (may be nil
// or empty for a self-signed leaf).
//
// Each certificate is already valid DER; PKIPathB64 wraps them verbatim as
// RawValue.FullBytes elements inside a single ASN.1 SEQUENCE.
func PKIPathB64(leafDER []byte, extraDER [][]byte) (string, error) {
	if len(leafDER) == 0 {
		return "", errors.New("pkipath: leafDER must not be empty")
	}

	vals := make([]asn1.RawValue, 0, 1+len(extraDER))
	vals = append(vals, asn1.RawValue{FullBytes: leafDER})
	for _, e := range extraDER {
		vals = append(vals, asn1.RawValue{FullBytes: e})
	}

	der, err := asn1.Marshal(vals)
	if err != nil {
		return "", fmt.Errorf("pkipath: marshal SEQUENCE OF Certificate: %w", err)
	}

	return base64.StdEncoding.EncodeToString(der), nil
}
