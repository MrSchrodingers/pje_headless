package signer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/MrSchrodingers/pje_headless/internal/signerpb"
)

// RemoteSigner implements signer.Signer by delegating all operations to a
// SignerService gRPC endpoint. The connection is established lazily on Login.
//
// SECURITY: uses plain TCP (insecure credentials). Acceptable only on a
// trusted loopback / LAN segment. mTLS is a backlog hardening item.
// Do NOT point RemoteSigner at an untrusted network address without TLS.
type RemoteSigner struct {
	addr string // e.g. "127.0.0.1:9090"

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client signerpb.SignerServiceClient
}

// NewRemoteSigner creates a RemoteSigner that will connect to addr on Login.
// addr must be a host:port string (e.g. "127.0.0.1:9090").
func NewRemoteSigner(addr string) *RemoteSigner {
	return &RemoteSigner{addr: addr}
}

// Login establishes the gRPC connection and verifies reachability via Health.
// It is idempotent: a second call is a no-op if the connection is already open.
func (r *RemoteSigner) Login(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn != nil {
		return nil
	}

	//nolint:staticcheck // grpc.Dial is the stable API for go 1.26 + grpc v1
	conn, err := grpc.NewClient(
		r.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("remote signer: connect %q: %w", r.addr, err)
	}

	client := signerpb.NewSignerServiceClient(conn)

	hs, err := client.Health(ctx, &signerpb.Empty{})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("remote signer: health check: %w", err)
	}
	if !hs.Ready {
		_ = conn.Close()
		return fmt.Errorf("remote signer: server not ready (no credential loaded)")
	}

	r.conn = conn
	r.client = client
	return nil
}

// Sign calls SignerService.Sign on the remote host.
func (r *RemoteSigner) Sign(ctx context.Context, phrase, algorithm string) (string, error) {
	cl, err := r.getClient()
	if err != nil {
		return "", err
	}
	reply, err := cl.Sign(ctx, &signerpb.SignRequest{Phrase: phrase, Algorithm: algorithm})
	if err != nil {
		return "", fmt.Errorf("remote signer: sign: %w", err)
	}
	return reply.SignatureB64, nil
}

// CertChainPKIPath calls SignerService.CertChainPKIPath on the remote host.
func (r *RemoteSigner) CertChainPKIPath(ctx context.Context) (string, error) {
	cl, err := r.getClient()
	if err != nil {
		return "", err
	}
	reply, err := cl.CertChainPKIPath(ctx, &signerpb.Empty{})
	if err != nil {
		return "", fmt.Errorf("remote signer: certchain: %w", err)
	}
	return reply.PkipathB64, nil
}

// Identity calls SignerService.Identity on the remote host.
func (r *RemoteSigner) Identity(ctx context.Context) (Identity, error) {
	cl, err := r.getClient()
	if err != nil {
		return Identity{}, err
	}
	msg, err := cl.Identity(ctx, &signerpb.Empty{})
	if err != nil {
		return Identity{}, fmt.Errorf("remote signer: identity: %w", err)
	}
	return Identity{
		Subject:  msg.Subject,
		Issuer:   msg.Issuer,
		Serial:   msg.Serial,
		NotAfter: time.Unix(msg.NotAfterUnix, 0).UTC(),
	}, nil
}

// Available probes the remote Health RPC without mutating state.
// Returns false if the connection is not yet established, if the RPC fails,
// or if the server reports Ready=false.
func (r *RemoteSigner) Available(ctx context.Context) bool {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()

	if cl == nil {
		return false
	}
	hs, err := cl.Health(ctx, &signerpb.Empty{})
	if err != nil {
		return false
	}
	return hs.Ready
}

// getClient returns the gRPC client or an error if Login has not been called.
func (r *RemoteSigner) getClient() (signerpb.SignerServiceClient, error) {
	r.mu.Lock()
	cl := r.client
	r.mu.Unlock()

	if cl == nil {
		return nil, fmt.Errorf("remote signer: not connected (Login must be called first)")
	}
	return cl, nil
}
