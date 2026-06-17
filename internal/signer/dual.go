package signer

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/MrSchrodingers/pje_headless/internal/audit"
)

// DualSigner implements Signer with a priority-ordered list of backends.
// The active backend is always the first one in the list that reports Available.
// When the active backend changes between calls (because the previous became
// unavailable), an audit.IdentitySwitch event is emitted at WARN level.
type DualSigner struct {
	order []Signer
	log   *slog.Logger

	mu          sync.Mutex
	lastSubject string // Subject of the last successfully resolved backend
}

// NewDual returns a DualSigner that picks the first Available backend from
// order on every call. order[0] has the highest priority.
func NewDual(order []Signer, log *slog.Logger) *DualSigner {
	return &DualSigner{order: order, log: log}
}

// Available reports true if at least one backend is Available.
func (d *DualSigner) Available(ctx context.Context) bool {
	for _, s := range d.order {
		if s.Available(ctx) {
			return true
		}
	}
	return false
}

// resolveActive returns the first Available backend and updates lastSubject,
// emitting audit.IdentitySwitch if the identity changed since the last call.
// An error is returned when no backend is available.
func (d *DualSigner) resolveActive(ctx context.Context) (Signer, error) {
	for _, s := range d.order {
		if !s.Available(ctx) {
			continue
		}
		// Attempt to read the identity for switch detection.
		// A failure here is non-fatal: skip tracking but still use the backend.
		if id, err := s.Identity(ctx); err == nil {
			curr := id.Subject
			d.mu.Lock()
			prev := d.lastSubject
			d.lastSubject = curr
			d.mu.Unlock()
			if prev != "" && prev != curr {
				audit.IdentitySwitch(d.log, prev, curr)
			}
		}
		return s, nil
	}
	return nil, errors.New("dual: nenhum backend de assinatura disponivel")
}

// Login delegates to the active backend.
func (d *DualSigner) Login(ctx context.Context) error {
	s, err := d.resolveActive(ctx)
	if err != nil {
		return err
	}
	return s.Login(ctx)
}

// Sign delegates to the active backend.
func (d *DualSigner) Sign(ctx context.Context, phrase, algorithm string) (string, error) {
	s, err := d.resolveActive(ctx)
	if err != nil {
		return "", err
	}
	return s.Sign(ctx, phrase, algorithm)
}

// CertChainPKIPath delegates to the active backend.
func (d *DualSigner) CertChainPKIPath(ctx context.Context) (string, error) {
	s, err := d.resolveActive(ctx)
	if err != nil {
		return "", err
	}
	return s.CertChainPKIPath(ctx)
}

// Identity delegates to the active backend.
func (d *DualSigner) Identity(ctx context.Context) (Identity, error) {
	s, err := d.resolveActive(ctx)
	if err != nil {
		return Identity{}, err
	}
	// resolveActive already called s.Identity internally for switch tracking,
	// but callers need the authoritative value returned directly.
	return s.Identity(ctx)
}
