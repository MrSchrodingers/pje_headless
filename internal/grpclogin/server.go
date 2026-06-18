// Package grpclogin implements the gRPC server side of the LoginService.
// LoginServiceServer wraps a BearerProvider (satisfied by *loginsvc.LoginManager)
// and exposes the two RPCs declared in proto/login.proto.
//
// SECURITY: plain TCP by default. Bind only to loopback or a trusted LAN
// interface (PJE_LOGIN_GRPC_ADDR). The bearer returned is a credential.
// mTLS hardening is tracked as a backlog item.
package grpclogin

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"

	"github.com/MrSchrodingers/pje_headless/internal/loginpb"
)

// BearerProvider is the interface that LoginServiceServer requires.
// *loginsvc.LoginManager satisfies it; tests inject a fake.
type BearerProvider interface {
	GetBearer(ctx context.Context, force bool) (bearer string, expiresAt time.Time, fromCache bool, err error)
	Snapshot() (hasBearer bool, expiresAt time.Time)
}

// LoginServiceServer wraps a BearerProvider and implements
// loginpb.LoginServiceServer.
type LoginServiceServer struct {
	loginpb.UnimplementedLoginServiceServer

	provider BearerProvider
	log      *slog.Logger
}

// NewLoginServiceServer returns a LoginServiceServer backed by provider.
// log may be nil; in that case a no-op logger is used.
func NewLoginServiceServer(provider BearerProvider, log *slog.Logger) *LoginServiceServer {
	if log == nil {
		log = slog.Default()
	}
	return &LoginServiceServer{provider: provider, log: log}
}

// GetBearer implements loginpb.LoginServiceServer.
func (s *LoginServiceServer) GetBearer(ctx context.Context, req *loginpb.GetBearerRequest) (*loginpb.BearerReply, error) {
	bearer, expiresAt, fromCache, err := s.provider.GetBearer(ctx, req.Force)
	if err != nil {
		return nil, fmt.Errorf("grpclogin: GetBearer: %w", err)
	}
	return &loginpb.BearerReply{
		Bearer:        bearer,
		ExpiresAtUnix: expUnix(expiresAt),
		FromCache:     fromCache,
	}, nil
}

// expUnix renders an expiry instant as a Unix timestamp, mapping the zero time
// (unknown expiry) to 0 to honor the proto contract ("0 when unknown"). A bare
// time.Time{}.Unix() yields a large negative value (-62135596800), which a
// consumer comparing now >= expires_at_unix would misread as "expired in year
// 0001"; returning 0 keeps the documented sentinel.
func expUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Health implements loginpb.LoginServiceServer.
// It calls Snapshot and does not trigger a login.
func (s *LoginServiceServer) Health(_ context.Context, _ *loginpb.Empty) (*loginpb.HealthStatus, error) {
	has, exp := s.provider.Snapshot()
	return &loginpb.HealthStatus{
		HasBearer:     has,
		ExpiresAtUnix: expUnix(exp),
	}, nil
}

// ListenAndServe starts the gRPC server on addr (e.g. ":9091") and blocks.
func ListenAndServe(addr string, srv *LoginServiceServer, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpclogin: listen %q: %w", addr, err)
	}
	return Serve(ln, srv, log)
}

// Serve registers srv on a new *grpc.Server and serves on ln until it closes.
// Separated from ListenAndServe so tests can inject a bufconn listener.
func Serve(ln net.Listener, srv *LoginServiceServer, log *slog.Logger) error {
	gs := grpc.NewServer()
	loginpb.RegisterLoginServiceServer(gs, srv)
	if log != nil {
		log.Info("LoginService gRPC ready", "addr", ln.Addr().String())
	}
	return gs.Serve(ln)
}
