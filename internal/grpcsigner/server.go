// Package grpcsigner implements the gRPC server side of the remote-signing
// topology. SignerService wraps a local signer.Signer and exposes the four
// RPCs declared in proto/signer.proto.
//
// SECURITY: plain TCP by default. Bind only to loopback or a trusted LAN
// interface (PJE_GRPC_ADDR). mTLS hardening is in the backlog.
package grpcsigner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/MrSchrodingers/pje_headless/internal/signerpb"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

// SignerServiceServer wraps a local signer.Signer and implements
// signerpb.SignerServiceServer. Login is performed lazily on the first RPC
// that requires a loaded credential.
type SignerServiceServer struct {
	signerpb.UnimplementedSignerServiceServer

	local signer.Signer
	log   *slog.Logger

	mu      sync.Mutex
	loggedIn bool
}

// NewSignerServiceServer returns a SignerServiceServer that delegates to local.
// log may be nil; in that case a no-op logger is used.
func NewSignerServiceServer(local signer.Signer, log *slog.Logger) *SignerServiceServer {
	if log == nil {
		log = slog.Default()
	}
	return &SignerServiceServer{local: local, log: log}
}

// ensureLogin calls Login at most once (lazy, idempotent under the mutex).
func (s *SignerServiceServer) ensureLogin(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loggedIn {
		return nil
	}
	if err := s.local.Login(ctx); err != nil {
		return fmt.Errorf("grpcsigner: login: %w", err)
	}
	s.loggedIn = true
	return nil
}

// Sign implements signerpb.SignerServiceServer.
func (s *SignerServiceServer) Sign(ctx context.Context, req *signerpb.SignRequest) (*signerpb.SignReply, error) {
	if err := s.ensureLogin(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	sig, err := s.local.Sign(ctx, req.Phrase, req.Algorithm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign: %v", err)
	}
	return &signerpb.SignReply{SignatureB64: sig}, nil
}

// CertChainPKIPath implements signerpb.SignerServiceServer.
func (s *SignerServiceServer) CertChainPKIPath(ctx context.Context, _ *signerpb.Empty) (*signerpb.Chain, error) {
	if err := s.ensureLogin(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	chain, err := s.local.CertChainPKIPath(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "certchain: %v", err)
	}
	return &signerpb.Chain{PkipathB64: chain}, nil
}

// Identity implements signerpb.SignerServiceServer.
func (s *SignerServiceServer) Identity(ctx context.Context, _ *signerpb.Empty) (*signerpb.IdentityMsg, error) {
	if err := s.ensureLogin(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	id, err := s.local.Identity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "identity: %v", err)
	}
	return &signerpb.IdentityMsg{
		Subject:      id.Subject,
		Issuer:       id.Issuer,
		Serial:       id.Serial,
		NotAfterUnix: id.NotAfter.Unix(),
	}, nil
}

// Health implements signerpb.SignerServiceServer.
// It does NOT call ensureLogin so that it remains a pure probe: if the
// credential is not yet loaded the service is not ready but also not broken.
func (s *SignerServiceServer) Health(ctx context.Context, _ *signerpb.Empty) (*signerpb.HealthStatus, error) {
	if !s.local.Available(ctx) {
		return &signerpb.HealthStatus{Ready: false}, nil
	}
	id, err := s.local.Identity(ctx)
	if err != nil {
		// Available returned true but Identity failed; report degraded.
		s.log.Warn("grpcsigner: Health: identity probe failed", "err", err)
		return &signerpb.HealthStatus{Ready: false}, nil
	}
	return &signerpb.HealthStatus{Ready: true, IdentitySubject: id.Subject}, nil
}

// ListenAndServe starts the gRPC server on addr (e.g. ":9090") and blocks.
// It is provided for convenience in the signer-only mode; callers that need
// more control over the listener should use Serve directly.
func ListenAndServe(addr string, srv *SignerServiceServer, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpcsigner: listen %q: %w", addr, err)
	}
	return Serve(ln, srv, log)
}

// Serve registers srv on a new *grpc.Server and serves on ln until it closes.
// It is separated from ListenAndServe so that tests can inject a bufconn listener.
func Serve(ln net.Listener, srv *SignerServiceServer, log *slog.Logger) error {
	gs := grpc.NewServer()
	signerpb.RegisterSignerServiceServer(gs, srv)
	if log != nil {
		log.Info("SignerService gRPC pronto", "addr", ln.Addr().String())
	}
	return gs.Serve(ln)
}
