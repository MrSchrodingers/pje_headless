package browser

import (
	"context"

	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// stubSigner is a no-op Signer used to construct a Browser in unit tests that
// never perform a real login (which needs Chrome and a certificate token).
type stubSigner struct{}

func (stubSigner) Login(context.Context) error                        { return nil }
func (stubSigner) Sign(context.Context, string, string) (string, error) { return "", nil }
func (stubSigner) CertChainPKIPath(context.Context) (string, error)   { return "", nil }
func (stubSigner) Identity(context.Context) (signer.Identity, error)  { return signer.Identity{}, nil }
func (stubSigner) Available(context.Context) bool                     { return true }
