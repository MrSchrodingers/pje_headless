package grpcsigner_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/MrSchrodingers/pje_headless/internal/grpcsigner"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
	"github.com/MrSchrodingers/pje_headless/internal/signerpb"
)

// fakeSigner is a deterministic in-process Signer used exclusively to verify
// the gRPC transport layer. It returns fixed values so the test can assert
// the exact bytes that travel through the wire without re-implementing
// crypto logic.
type fakeSigner struct{}

const (
	fakeSignature = "ZmFrZXNpZ25hdHVyZQ==" // base64("fakesignature")
	fakePKIPath   = "ZmFrZXBraXBhdGg="     // base64("fakepkipath")
	fakeSubject   = "CN=Fake Signer,O=Test"
	fakeIssuer    = "CN=Fake CA,O=Test"
	fakeSerial    = "42"
)

var fakeNotAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func (f *fakeSigner) Login(_ context.Context) error { return nil }

func (f *fakeSigner) Sign(_ context.Context, _, _ string) (string, error) {
	return fakeSignature, nil
}

func (f *fakeSigner) CertChainPKIPath(_ context.Context) (string, error) {
	return fakePKIPath, nil
}

func (f *fakeSigner) Identity(_ context.Context) (signer.Identity, error) {
	return signer.Identity{
		Subject:  fakeSubject,
		Issuer:   fakeIssuer,
		Serial:   fakeSerial,
		NotAfter: fakeNotAfter,
	}, nil
}

func (f *fakeSigner) Available(_ context.Context) bool { return true }

// newInProcessPair starts a SignerService backed by fake and returns a gRPC
// client connected to it through a bufconn listener (no network sockets).
// The returned cleanup function stops the server and closes the connection.
func newInProcessPair(t *testing.T, fake signer.Signer) (signerpb.SignerServiceClient, func()) {
	t.Helper()

	const bufSize = 1 << 20 // 1 MiB
	lis := bufconn.Listen(bufSize)

	srv := grpcsigner.NewSignerServiceServer(fake, nil)
	gs := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(gs, srv)

	go func() { _ = gs.Serve(lis) }()

	//nolint:staticcheck
	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}

	return signerpb.NewSignerServiceClient(conn), cleanup
}

// TestSignRoundtrip verifies that a Sign RPC sent through gRPC arrives at the
// fakeSigner and the signature bytes are returned unchanged to the caller.
func TestSignRoundtrip(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newInProcessPair(t, &fakeSigner{})
	defer cleanup()

	reply, err := client.Sign(ctx, &signerpb.SignRequest{
		Phrase:    "hello",
		Algorithm: "SHA256withRSA",
	})
	if err != nil {
		t.Fatalf("Sign RPC failed: %v", err)
	}
	if reply.SignatureB64 != fakeSignature {
		t.Errorf("got signature %q, want %q", reply.SignatureB64, fakeSignature)
	}
}

// TestCertChainRoundtrip verifies the CertChainPKIPath RPC.
func TestCertChainRoundtrip(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newInProcessPair(t, &fakeSigner{})
	defer cleanup()

	reply, err := client.CertChainPKIPath(ctx, &signerpb.Empty{})
	if err != nil {
		t.Fatalf("CertChainPKIPath RPC failed: %v", err)
	}
	if reply.PkipathB64 != fakePKIPath {
		t.Errorf("got pkipath %q, want %q", reply.PkipathB64, fakePKIPath)
	}
}

// TestIdentityRoundtrip verifies that all Identity fields survive the
// protobuf encoding/decoding round trip without loss.
func TestIdentityRoundtrip(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newInProcessPair(t, &fakeSigner{})
	defer cleanup()

	reply, err := client.Identity(ctx, &signerpb.Empty{})
	if err != nil {
		t.Fatalf("Identity RPC failed: %v", err)
	}
	if reply.Subject != fakeSubject {
		t.Errorf("Subject: got %q, want %q", reply.Subject, fakeSubject)
	}
	if reply.Issuer != fakeIssuer {
		t.Errorf("Issuer: got %q, want %q", reply.Issuer, fakeIssuer)
	}
	if reply.Serial != fakeSerial {
		t.Errorf("Serial: got %q, want %q", reply.Serial, fakeSerial)
	}
	if reply.NotAfterUnix != fakeNotAfter.Unix() {
		t.Errorf("NotAfterUnix: got %d, want %d", reply.NotAfterUnix, fakeNotAfter.Unix())
	}
}

// TestHealthReady verifies that Health returns Ready=true and the identity
// subject when the underlying signer is available.
func TestHealthReady(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newInProcessPair(t, &fakeSigner{})
	defer cleanup()

	hs, err := client.Health(ctx, &signerpb.Empty{})
	if err != nil {
		t.Fatalf("Health RPC failed: %v", err)
	}
	if !hs.Ready {
		t.Error("expected Ready=true, got false")
	}
	if hs.IdentitySubject != fakeSubject {
		t.Errorf("IdentitySubject: got %q, want %q", hs.IdentitySubject, fakeSubject)
	}
}

// unavailableSigner returns Available=false to exercise the degraded Health path.
type unavailableSigner struct{ fakeSigner }

func (u *unavailableSigner) Available(_ context.Context) bool { return false }

// TestHealthNotReady verifies that Health returns Ready=false when the
// underlying signer reports itself unavailable.
func TestHealthNotReady(t *testing.T) {
	ctx := context.Background()
	client, cleanup := newInProcessPair(t, &unavailableSigner{})
	defer cleanup()

	hs, err := client.Health(ctx, &signerpb.Empty{})
	if err != nil {
		t.Fatalf("Health RPC failed: %v", err)
	}
	if hs.Ready {
		t.Error("expected Ready=false for unavailable signer, got true")
	}
}
