package loginsvc

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// defaultRefreshMargin is how far before expiry a cached token is considered
	// stale and a new login is triggered proactively.
	defaultRefreshMargin = 60 * time.Second

	// defaultTTL is used when a token's expiry cannot be parsed from its JWT
	// payload.  It is deliberately short so the token is refreshed soon.
	defaultTTL = 5 * time.Minute
)

// inflight represents a login that is currently in progress.  Multiple callers
// that arrive while a login is running attach to the same inflight and share
// its result (coalescing).
type inflight struct {
	done   chan struct{} // closed when the login completes
	bearer string
	exp    time.Time
	err    error
}

// LoginManager owns the cached bearer and the loginFn that produces it.
// It is safe for concurrent use.
type LoginManager struct {
	loginFn       func(context.Context) (string, error)
	refreshMargin time.Duration
	log           *slog.Logger

	mu        sync.Mutex
	bearer    string
	expiresAt time.Time // zero means "not yet set"
	flight    *inflight // non-nil when a login is in progress
}

// NewManager returns a LoginManager that calls loginFn to obtain a bearer.
// refreshMargin determines how early before expiry a refresh is triggered;
// pass 0 to use defaultRefreshMargin.  log may be nil.
func NewManager(
	loginFn func(context.Context) (string, error),
	refreshMargin time.Duration,
	log *slog.Logger,
) *LoginManager {
	if refreshMargin <= 0 {
		refreshMargin = defaultRefreshMargin
	}
	if log == nil {
		log = slog.Default()
	}
	return &LoginManager{
		loginFn:       loginFn,
		refreshMargin: refreshMargin,
		log:           log,
	}
}

// GetBearer returns a valid bearer token.
//
// Fast path (mutex held): if !force and a bearer is cached and it has not yet
// crossed the (expiresAt - refreshMargin) boundary, it is returned immediately
// with fromCache=true.
//
// Slow path: a new login is needed.  Concurrent callers coalesce: only one
// loginFn invocation runs; the rest attach to the in-flight result.
func (m *LoginManager) GetBearer(ctx context.Context, force bool) (bearer string, expiresAt time.Time, fromCache bool, err error) {
	m.mu.Lock()

	// Fast path.
	if !force && m.bearer != "" && m.isFresh() {
		b, exp := m.bearer, m.expiresAt
		m.mu.Unlock()
		return b, exp, true, nil
	}

	// Slow path: attach to or start an in-flight login.
	if m.flight == nil {
		// This goroutine is the winner; start the login.
		f := &inflight{done: make(chan struct{})}
		m.flight = f
		m.mu.Unlock()

		b, loginErr := m.loginFn(ctx)

		m.mu.Lock()
		m.flight = nil // clear before broadcasting
		if loginErr == nil {
			exp, ok := parseBearerExp(b)
			if !ok {
				exp = time.Now().Add(defaultTTL)
			}
			m.bearer = b
			m.expiresAt = exp
			f.bearer = b
			f.exp = exp
		}
		f.err = loginErr
		close(f.done) // broadcast to all waiting goroutines
		m.mu.Unlock()

		return f.bearer, f.exp, false, f.err
	}

	// Another goroutine is already running loginFn; attach to it.
	f := m.flight
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		return "", time.Time{}, false, fmt.Errorf("loginsvc: GetBearer: context cancelled while waiting for in-flight login: %w", ctx.Err())
	case <-f.done:
	}

	return f.bearer, f.exp, false, f.err
}

// Snapshot returns the current cache state without triggering a login.
// It is used by the Health RPC. hasBearer reports whether a NON-EXPIRED bearer
// is cached (honoring the proto's "non-expired" contract): a cached-but-stale
// token reports hasBearer=false, since the next GetBearer would re-login anyway.
// expiresAt is returned regardless so the caller can see when the cached token
// (if any) lapses.
func (m *LoginManager) Snapshot() (hasBearer bool, expiresAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bearer != "" && m.isFresh(), m.expiresAt
}

// isFresh reports whether the current cached bearer is still usable given
// the configured refresh margin.  Must be called with m.mu held.
func (m *LoginManager) isFresh() bool {
	if m.expiresAt.IsZero() {
		// No expiry info: treat as stale.
		return false
	}
	return time.Now().Before(m.expiresAt.Add(-m.refreshMargin))
}

// primeCache directly sets the bearer and expiresAt without calling loginFn.
// It exists solely to make certain expiry-edge-case tests deterministic, by
// bypassing the loginFn entirely.  It is unexported so it is only callable
// from within the package (tests live in package loginsvc).
func (m *LoginManager) primeCache(bearer string, expiresAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bearer = bearer
	m.expiresAt = expiresAt
}
