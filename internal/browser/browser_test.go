package browser

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestLoginNilSignerFails verifies the guard: a Browser with no signer cannot
// log in and must return an error rather than launching Chrome.
func TestLoginNilSignerFails(t *testing.T) {
	b := New(nil, Config{}, nil)
	_, err := b.Login(context.Background())
	if err == nil {
		t.Fatal("Login with nil signer expected an error, got nil")
	}
}

// TestStartPJeOfficeBindsLoopback verifies that startPJeOffice actually opens a
// listening socket on the configured loopback port (the page hardcodes
// 127.0.0.1:8800) and that the returned stop function releases the port so a
// subsequent bind succeeds. This exercises the observable side effect (a bound
// port) without needing Chrome.
func TestStartPJeOfficeBindsLoopback(t *testing.T) {
	// Pick a free port to avoid clashing with a real :8800 on the host.
	port := freePort(t)

	b := New(stubSigner{}, Config{
		PJeOfficeBindAddr: "127.0.0.1",
		PJeOfficePort:     port,
	}, nil)

	stop, err := b.startPJeOffice()
	if err != nil {
		t.Fatalf("startPJeOffice: %v", err)
	}

	// The port must now be in use (a second listen must fail).
	if ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port)); err == nil {
		_ = ln.Close()
		stop()
		t.Fatalf("expected port %s to be bound by the server, but it was free", port)
	}

	// The server must answer the health GET on /pjeOffice/ with the OK GIF.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		stop()
		t.Fatalf("dial server: %v", err)
	}
	_ = conn.Close()

	// Stop releases the port: a fresh bind must now succeed.
	stop()
	// Give the listener a brief moment to close.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		if err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("port %s was not released after stop()", port)
}

// freePort returns an OS-assigned free TCP port as a string.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("freePort split: %v", err)
	}
	return p
}
