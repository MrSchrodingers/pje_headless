package grpclogin_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/MrSchrodingers/pje_headless/internal/grpclogin"
	"github.com/MrSchrodingers/pje_headless/internal/loginpb"
)

// fakeProvider is a deterministic in-process BearerProvider used exclusively
// to verify that the gRPC transport maps request fields to the provider and
// fills reply fields correctly.
type fakeProvider struct {
	bearer    string
	expiresAt time.Time
	fromCache bool
	err       error

	// snapshot state for Health
	hasBearer   bool
	snapshotExp time.Time
}

func (f *fakeProvider) GetBearer(_ context.Context, force bool) (string, time.Time, bool, error) {
	// The fake ignores force for simplicity; the test for force routing is
	// handled by inspecting the forceProvider below.
	return f.bearer, f.expiresAt, f.fromCache, f.err
}

func (f *fakeProvider) Snapshot() (bool, time.Time) {
	return f.hasBearer, f.snapshotExp
}

// forceCapture records the last force value passed to GetBearer.
type forceCapture struct {
	fakeProvider
	capturedForce bool
}

func (fc *forceCapture) GetBearer(ctx context.Context, force bool) (string, time.Time, bool, error) {
	fc.capturedForce = force
	return fc.fakeProvider.GetBearer(ctx, force)
}

// newInProcessPair starts a LoginService backed by provider and returns a gRPC
// client connected through a bufconn listener (no OS network sockets).
func newInProcessPair(t *testing.T, provider grpclogin.BearerProvider) (loginpb.LoginServiceClient, func()) {
	t.Helper()

	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	srv := grpclogin.NewLoginServiceServer(provider, nil)
	gs := grpc.NewServer()
	loginpb.RegisterLoginServiceServer(gs, srv)

	go func() { _ = gs.Serve(lis) }()

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
	return loginpb.NewLoginServiceClient(conn), cleanup
}

// TestGetBearerRoundtrip verifies that bearer, expires_at_unix, and from_cache
// survive the protobuf encoding/decoding round trip without mutation.
func TestGetBearerRoundtrip(t *testing.T) {
	expTime := time.Unix(9999999999, 0)
	provider := &fakeProvider{
		bearer:    "bearer eyJtest",
		expiresAt: expTime,
		fromCache: true,
	}

	client, cleanup := newInProcessPair(t, provider)
	defer cleanup()

	reply, err := client.GetBearer(context.Background(), &loginpb.GetBearerRequest{Force: false})
	if err != nil {
		t.Fatalf("GetBearer RPC failed: %v", err)
	}
	if reply.Bearer != provider.bearer {
		t.Errorf("Bearer: got %q, want %q", reply.Bearer, provider.bearer)
	}
	if reply.ExpiresAtUnix != expTime.Unix() {
		t.Errorf("ExpiresAtUnix: got %d, want %d", reply.ExpiresAtUnix, expTime.Unix())
	}
	if !reply.FromCache {
		t.Error("FromCache: got false, want true")
	}
}

// TestGetBearerForceRouted verifies that the force=true flag in the request is
// forwarded to the provider's GetBearer method.
func TestGetBearerForceRouted(t *testing.T) {
	fc := &forceCapture{
		fakeProvider: fakeProvider{
			bearer:    "bearer eyJforced",
			expiresAt: time.Unix(9999999999, 0),
			fromCache: false,
		},
	}

	client, cleanup := newInProcessPair(t, fc)
	defer cleanup()

	_, err := client.GetBearer(context.Background(), &loginpb.GetBearerRequest{Force: true})
	if err != nil {
		t.Fatalf("GetBearer RPC failed: %v", err)
	}
	if !fc.capturedForce {
		t.Error("force=true was not forwarded to the provider")
	}
}

// TestHealthMapsSnapshot verifies that Health maps Snapshot -> has_bearer and
// expires_at_unix correctly.
func TestHealthMapsSnapshot(t *testing.T) {
	expTime := time.Unix(8888888888, 0)
	provider := &fakeProvider{
		hasBearer:   true,
		snapshotExp: expTime,
	}

	client, cleanup := newInProcessPair(t, provider)
	defer cleanup()

	hs, err := client.Health(context.Background(), &loginpb.Empty{})
	if err != nil {
		t.Fatalf("Health RPC failed: %v", err)
	}
	if !hs.HasBearer {
		t.Error("HasBearer: got false, want true")
	}
	if hs.ExpiresAtUnix != expTime.Unix() {
		t.Errorf("ExpiresAtUnix: got %d, want %d", hs.ExpiresAtUnix, expTime.Unix())
	}
}

// TestHealthNoBearerCached verifies that Health reports has_bearer=false when
// no bearer is cached.
func TestHealthNoBearerCached(t *testing.T) {
	provider := &fakeProvider{hasBearer: false}

	client, cleanup := newInProcessPair(t, provider)
	defer cleanup()

	hs, err := client.Health(context.Background(), &loginpb.Empty{})
	if err != nil {
		t.Fatalf("Health RPC failed: %v", err)
	}
	if hs.HasBearer {
		t.Error("HasBearer: got true, want false")
	}
	// With no bearer the expiry is unknown; the proto contract is "0 when
	// unknown". A bare time.Time{}.Unix() would leak -62135596800, which a
	// consumer comparing now >= expires_at_unix misreads. Pin the sentinel.
	if hs.ExpiresAtUnix != 0 {
		t.Errorf("ExpiresAtUnix with no bearer: got %d, want 0 (unknown sentinel)", hs.ExpiresAtUnix)
	}
}
