package signer_test

// Tests for DualSigner: priority + fallback + identity-switch audit.
// All cases run without hardware; fakeSigner simulates backends.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MrSchrodingers/pje_headless/internal/audit"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// fakeSigner is a controllable in-memory implementation of signer.Signer.
// Fields may be mutated from tests to simulate state changes (e.g. a token
// being removed mid-flight). Access from multiple goroutines must be guarded
// by the caller; the struct itself uses a mutex only for the fields mutated
// concurrently in the race test.
type fakeSigner struct {
	mu        sync.Mutex
	available bool
	id        string   // becomes Identity.Subject
	loginErr  error
	signErr   error
}

func (f *fakeSigner) setAvailable(v bool) {
	f.mu.Lock()
	f.available = v
	f.mu.Unlock()
}

func (f *fakeSigner) Available(_ context.Context) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}

func (f *fakeSigner) Login(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginErr
}

func (f *fakeSigner) Sign(_ context.Context, _, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.signErr != nil {
		return "", f.signErr
	}
	return "sig:" + f.id, nil
}

func (f *fakeSigner) CertChainPKIPath(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return "pkipath:" + f.id, nil
}

func (f *fakeSigner) Identity(_ context.Context) (signer.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return signer.Identity{
		Subject:  f.id,
		Issuer:   "FakeCA",
		Serial:   "1",
		NotAfter: time.Now().Add(time.Hour),
	}, nil
}

// --- (a) usa o backend de maior prioridade quando ambos estao disponiveis ------

func TestDualUsesHighestPriorityBackend(t *testing.T) {
	a := &fakeSigner{available: true, id: "Alice"}
	b := &fakeSigner{available: true, id: "Bob"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	ctx := context.Background()
	if err := d.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	id, err := d.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Subject != "Alice" {
		t.Fatalf("expected Subject=Alice (highest priority), got %q", id.Subject)
	}

	sig, err := d.Sign(ctx, "payload", "SHA256withRSA")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig != "sig:Alice" {
		t.Fatalf("expected sign result from Alice, got %q", sig)
	}
}

// --- (b) cai para o proximo quando o primeiro tem Available=false ---------------

func TestDualFallsBackWhenPrimaryUnavailable(t *testing.T) {
	a := &fakeSigner{available: false, id: "Bruna"}
	b := &fakeSigner{available: true, id: "Marcos"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	ctx := context.Background()
	if err := d.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	id, err := d.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Subject != "Marcos" {
		t.Fatalf("expected Subject=Marcos (fallback), got %q", id.Subject)
	}

	sig, err := d.Sign(ctx, "payload", "SHA256withRSA")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig != "sig:Marcos" {
		t.Fatalf("expected sign result from Marcos, got %q", sig)
	}
}

// --- (b2) CertChainPKIPath delega ao backend ativo correto ---------------------

func TestDualCertChainDelegatesToActiveBackend(t *testing.T) {
	a := &fakeSigner{available: false, id: "Bruna"}
	b := &fakeSigner{available: true, id: "Marcos"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	ctx := context.Background()
	pkipath, err := d.CertChainPKIPath(ctx)
	if err != nil {
		t.Fatalf("CertChainPKIPath: %v", err)
	}
	// fakeSigner.CertChainPKIPath returns "pkipath:<id>"; must come from Marcos.
	if pkipath != "pkipath:Marcos" {
		t.Fatalf("expected CertChainPKIPath from Marcos (fallback), got %q", pkipath)
	}
}

// --- (c) ao trocar de identidade entre chamadas, emite identity_switch ----------

func TestDualFallbackEmitsIdentitySwitch(t *testing.T) {
	a := &fakeSigner{available: true, id: "Bruna"}
	b := &fakeSigner{available: true, id: "Marcos"}
	var buf bytes.Buffer
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(&buf))

	ctx := context.Background()
	// First call: active=Bruna; lastSubject registers as "Bruna".
	if err := d.Login(ctx); err != nil {
		t.Fatalf("Login (Bruna): %v", err)
	}

	// Make the primary unavailable; next call must fall back to Marcos.
	a.setAvailable(false)

	// Second call: active changes Bruna->Marcos; identity_switch must be emitted.
	if _, err := d.Sign(ctx, "x", "SHA256withRSA"); err != nil {
		t.Fatalf("Sign (fallback): %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "identity_switch") {
		t.Fatalf("expected identity_switch event in log; got:\n%s", out)
	}
	// Verify the JSON keys explicitly so that an arg-inversion in
	// audit.IdentitySwitch(log, prev, curr) would be caught here.
	if !strings.Contains(out, `"from":"Bruna"`) {
		t.Fatalf("expected \"from\":\"Bruna\" in log; got:\n%s", out)
	}
	if !strings.Contains(out, `"to":"Marcos"`) {
		t.Fatalf("expected \"to\":\"Marcos\" in log; got:\n%s", out)
	}
}

// --- subcase: Available() returns true when at least one backend is available --

func TestDualAvailableReflectsAnyBackend(t *testing.T) {
	a := &fakeSigner{available: false, id: "Bruna"}
	b := &fakeSigner{available: true, id: "Marcos"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	if !d.Available(context.Background()) {
		t.Fatal("expected Available=true when at least one backend is available")
	}

	a.setAvailable(false)
	b.setAvailable(false)
	if d.Available(context.Background()) {
		t.Fatal("expected Available=false when all backends are unavailable")
	}
}

// --- (d) nenhum backend Available -> Login e Sign retornam erro explicito -------

func TestDualNoAvailableReturnsError(t *testing.T) {
	a := &fakeSigner{available: false, id: "Bruna"}
	b := &fakeSigner{available: false, id: "Marcos"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	ctx := context.Background()
	if err := d.Login(ctx); err == nil {
		t.Fatal("Login: expected error when no backend available, got nil")
	}
	if _, err := d.Sign(ctx, "x", "SHA256withRSA"); err == nil {
		t.Fatal("Sign: expected error when no backend available, got nil")
	}
	if _, err := d.CertChainPKIPath(ctx); err == nil {
		t.Fatal("CertChainPKIPath: expected error when no backend available, got nil")
	}
	if _, err := d.Identity(ctx); err == nil {
		t.Fatal("Identity: expected error when no backend available, got nil")
	}
}

// --- edge: lista vazia de signers ----------------------------------------------

func TestDualEmptyOrderReturnsError(t *testing.T) {
	d := signer.NewDual([]signer.Signer{}, audit.New(io.Discard))

	ctx := context.Background()
	if err := d.Login(ctx); err == nil {
		t.Fatal("Login: expected error for empty signer list, got nil")
	}
	if d.Available(ctx) {
		t.Fatal("Available: expected false for empty signer list")
	}
}

// --- edge: propagacao de loginErr do backend ativo ----------------------------

func TestDualPropagatesLoginError(t *testing.T) {
	wantErr := errors.New("token removido")
	a := &fakeSigner{available: true, id: "Alice", loginErr: wantErr}
	d := signer.NewDual([]signer.Signer{a}, audit.New(io.Discard))

	if err := d.Login(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped loginErr, got %v", err)
	}
}

// --- race: chamadas concorrentes nao causam data race -------------------------

func TestDualConcurrentCallsNoRace(t *testing.T) {
	a := &fakeSigner{available: true, id: "Alice"}
	b := &fakeSigner{available: true, id: "Bob"}
	d := signer.NewDual([]signer.Signer{a, b}, audit.New(io.Discard))

	ctx := context.Background()
	if err := d.Login(ctx); err != nil {
		t.Fatal(err)
	}

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = d.Login(ctx)
		}()
		go func() {
			defer wg.Done()
			_, _ = d.Sign(ctx, "nonce", "SHA256withRSA")
		}()
		go func() {
			defer wg.Done()
			// Toggle availability to trigger switch detection paths.
			a.setAvailable(i%2 == 0)
		}()
	}
	wg.Wait()
}
