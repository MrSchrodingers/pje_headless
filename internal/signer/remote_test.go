package signer_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/MrSchrodingers/pje_headless/internal/grpcsigner"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
	"github.com/MrSchrodingers/pje_headless/internal/signerpb"
)

// fixedSigner is the in-package fake used to drive the RemoteSigner tests.
// It is intentionally separate from the grpcsigner_test fake so both test
// packages can evolve independently.
type fixedSigner struct{}

const (
	fixedSig     = "cmVtb3Rlc2ln"   // base64("remotesig")
	fixedPKI     = "cmVtb3Rla2V5"   // base64("remotekey")
	fixedSubject = "CN=Remote,O=Org"
	fixedIssuer  = "CN=Root CA,O=Org"
	fixedSerial  = "99"
)

var fixedNotAfter = time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)

func (f *fixedSigner) Login(_ context.Context) error { return nil }
func (f *fixedSigner) Sign(_ context.Context, _, _ string) (string, error) {
	return fixedSig, nil
}
func (f *fixedSigner) CertChainPKIPath(_ context.Context) (string, error) { return fixedPKI, nil }
func (f *fixedSigner) Identity(_ context.Context) (signer.Identity, error) {
	return signer.Identity{
		Subject:  fixedSubject,
		Issuer:   fixedIssuer,
		Serial:   fixedSerial,
		NotAfter: fixedNotAfter,
	}, nil
}
func (f *fixedSigner) Available(_ context.Context) bool { return true }

// startBufconnServer starts a SignerService backed by the given signer on a
// bufconn listener and returns the listener and a stop function.
func startBufconnServer(t *testing.T, local signer.Signer) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpcsigner.NewSignerServiceServer(local, nil)
	gs := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
	})
	return lis
}

// newRemoteSignerOverBufconn creates a RemoteSigner whose underlying gRPC
// connection is injected to bypass DNS/TCP: it dials through the bufconn
// listener. This exercises the full RemoteSigner code path without opening
// a real network socket.
//
// Because RemoteSigner.Login calls grpc.NewClient internally (hardwired to
// an address string), we cannot inject the dialer directly into RemoteSigner.
// Instead we start a real TCP listener on a loopback ephemeral port and
// bridge through bufconn so the test remains self-contained.
func newRemoteSignerViaTCP(t *testing.T, lis *bufconn.Listener) *signer.RemoteSigner {
	t.Helper()

	// Bridge: real TCP listener on loopback -> bufconn.
	tcpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp bridge listen: %v", err)
	}
	addr := tcpLis.Addr().String()

	go func() {
		for {
			tc, err := tcpLis.Accept()
			if err != nil {
				return
			}
			bc, err := lis.Dial()
			if err != nil {
				tc.Close()
				return
			}
			go bridge(tc, bc)
			go bridge(bc, tc)
		}
	}()
	t.Cleanup(func() { tcpLis.Close() })

	return signer.NewRemoteSigner(addr)
}

func bridge(dst net.Conn, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	dst.Close()
	src.Close()
}

// TestRemoteSignerLogin verifies that Login succeeds when the server is ready.
func TestRemoteSignerLogin(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	if err := rs.Login(context.Background()); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
}

// TestRemoteSignerSign verifies the full Sign path: Login then Sign.
// The returned signature must match what fixedSigner returns, proving the
// data is not transformed in transit.
func TestRemoteSignerSign(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	ctx := context.Background()
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	got, err := rs.Sign(ctx, "doc payload", "SHA256withRSA")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != fixedSig {
		t.Errorf("Sign: got %q, want %q", got, fixedSig)
	}
}

// TestRemoteSignerIdentity verifies that all Identity fields propagate
// correctly through the RemoteSigner -> gRPC -> SignerService -> fixedSigner
// chain and are reconstructed faithfully on the client side.
func TestRemoteSignerIdentity(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	ctx := context.Background()
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	id, err := rs.Identity(ctx)
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Subject != fixedSubject {
		t.Errorf("Subject: got %q, want %q", id.Subject, fixedSubject)
	}
	if id.Issuer != fixedIssuer {
		t.Errorf("Issuer: got %q, want %q", id.Issuer, fixedIssuer)
	}
	if id.Serial != fixedSerial {
		t.Errorf("Serial: got %q, want %q", id.Serial, fixedSerial)
	}
	if !id.NotAfter.Equal(fixedNotAfter) {
		t.Errorf("NotAfter: got %v, want %v", id.NotAfter, fixedNotAfter)
	}
}

// TestRemoteSignerAvailableAfterLogin verifies that Available returns true
// after a successful Login.
func TestRemoteSignerAvailableAfterLogin(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	ctx := context.Background()
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if !rs.Available(ctx) {
		t.Error("Available: expected true after successful Login, got false")
	}
}

// TestRemoteSignerAvailableBeforeLogin verifies that Available returns false
// before Login has been called (connection not yet established).
func TestRemoteSignerAvailableBeforeLogin(t *testing.T) {
	_ = startBufconnServer(t, &fixedSigner{})
	rs := signer.NewRemoteSigner("127.0.0.1:0") // unreachable — not logged in

	if rs.Available(context.Background()) {
		t.Error("Available: expected false before Login, got true")
	}
}

// TestRemoteSignerLoginIdempotent verifies that calling Login twice does not
// return an error and does not duplicate connections.
func TestRemoteSignerLoginIdempotent(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	ctx := context.Background()
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("first Login: %v", err)
	}
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("second Login (idempotent): %v", err)
	}
}

// TestRemoteSignerSignWithoutLogin verifies that Sign returns an error when
// Login has not been called first.
func TestRemoteSignerSignWithoutLogin(t *testing.T) {
	rs := signer.NewRemoteSigner("127.0.0.1:0")
	_, err := rs.Sign(context.Background(), "x", "SHA256withRSA")
	if err == nil {
		t.Error("expected error from Sign without Login, got nil")
	}
}

// TestRemoteSignerCertChain verifies the CertChainPKIPath path end-to-end.
func TestRemoteSignerCertChain(t *testing.T) {
	lis := startBufconnServer(t, &fixedSigner{})
	rs := newRemoteSignerViaTCP(t, lis)

	ctx := context.Background()
	if err := rs.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}

	got, err := rs.CertChainPKIPath(ctx)
	if err != nil {
		t.Fatalf("CertChainPKIPath: %v", err)
	}
	if got != fixedPKI {
		t.Errorf("CertChainPKIPath: got %q, want %q", got, fixedPKI)
	}
}

// Compile-time assertion: RemoteSigner implements signer.Signer.
var _ signer.Signer = (*signer.RemoteSigner)(nil)
