// export_test.go exposes internal byte slices for use in black-box tests
// (package pjeoffice_test). The file is only compiled during `go test`.
package pjeoffice

// GifOK returns a copy of the success GIF bytes so external tests can assert
// the exact response body rather than only its length.
func GifOK() []byte {
	cp := make([]byte, len(gifOK))
	copy(cp, gifOK)
	return cp
}

// GifErr returns a copy of the error GIF bytes so external tests can assert
// the exact response body rather than only its length.
func GifErr() []byte {
	cp := make([]byte, len(gifErr))
	copy(cp, gifErr)
	return cp
}
