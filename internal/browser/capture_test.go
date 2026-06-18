package browser

import (
	"testing"
)

// TestBearerCaptureMatchesAPIRequest verifies the core selenium-wire
// replacement: given CDP network events, the capture must return the
// Authorization header of the FIRST request whose URL matches the target
// pattern (/api/v2/processos/...), reading the value from the ExtraInfo event
// (raw headers as sent over the wire), correlated by RequestID.
func TestBearerCaptureMatchesAPIRequest(t *testing.T) {
	c := newBearerCapture()

	// Unrelated request (analytics) must be ignored even though it has an auth header.
	c.onRequest("req-1", "https://www.clarity.ms/collect")
	c.onExtraInfo("req-1", map[string]any{"Authorization": "Bearer SHOULD_BE_IGNORED"})

	// The real API request. requestWillBeSent carries the URL; the bearer
	// arrives in the ExtraInfo (raw headers), as the Angular app injects it.
	c.onRequest("req-2", "https://portaldeservicos.pdpj.jus.br/api/v2/processos/0710802")
	c.onExtraInfo("req-2", map[string]any{
		"accept":        "application/json",
		"Authorization": "Bearer eyJABC.tok.123",
	})

	got, ok := c.bearer()
	if !ok {
		t.Fatal("expected a captured bearer, got none")
	}
	if got != "Bearer eyJABC.tok.123" {
		t.Fatalf("captured %q, want %q", got, "Bearer eyJABC.tok.123")
	}
}

// TestBearerCaptureMatchesLiveQueryFormURL pins the exact URL the live PDPJ
// consulta fires: GET /api/v2/processos?numeroProcesso=<n>, where the process
// number is a query parameter and the path has NO trailing slash. The earlier
// matcher required "/api/v2/processos/" (trailing slash) and silently missed
// this real, authenticated (HTTP 200) request, so the bearer was never captured.
// This test fails if the trailing slash is reintroduced.
func TestBearerCaptureMatchesLiveQueryFormURL(t *testing.T) {
	c := newBearerCapture()

	const liveURL = "https://portaldeservicos.pdpj.jus.br/api/v2/processos?numeroProcesso=07108025520188020001"
	c.onRequest("req-live", liveURL)
	c.onExtraInfo("req-live", map[string]any{"authorization": "bearer eyJlive.tok.999"})

	got, ok := c.bearer()
	if !ok {
		t.Fatalf("expected a captured bearer for the live query-form URL %q, got none", liveURL)
	}
	if got != "bearer eyJlive.tok.999" {
		t.Fatalf("captured %q, want %q (full value verbatim, including the scheme prefix)", got, "bearer eyJlive.tok.999")
	}
}

// TestBearerCaptureExtraInfoBeforeRequest verifies the events can arrive in any
// order: ExtraInfo may be delivered before the matching requestWillBeSent.
func TestBearerCaptureExtraInfoBeforeRequest(t *testing.T) {
	c := newBearerCapture()

	c.onExtraInfo("req-9", map[string]any{"authorization": "Bearer lower.case.header"})
	c.onRequest("req-9", "https://portaldeservicos.pdpj.jus.br/api/v2/processos/123")

	got, ok := c.bearer()
	if !ok {
		t.Fatal("expected a captured bearer when ExtraInfo arrives first, got none")
	}
	// Header name matching must be case-insensitive (CDP may lower-case headers).
	if got != "Bearer lower.case.header" {
		t.Fatalf("captured %q, want %q", got, "Bearer lower.case.header")
	}
}

// TestBearerCaptureNoMatch verifies that a matching URL without any
// Authorization header does not yield a (false) capture.
func TestBearerCaptureNoMatch(t *testing.T) {
	c := newBearerCapture()

	c.onRequest("req-3", "https://portaldeservicos.pdpj.jus.br/api/v2/processos/0710802")
	c.onExtraInfo("req-3", map[string]any{"accept": "application/json"})

	if _, ok := c.bearer(); ok {
		t.Fatal("expected no bearer when the matching request has no Authorization header")
	}
}

// TestBearerCaptureIgnoresEmptyAuth verifies that an empty Authorization value
// on a matching request is treated as no capture (not a successful "" token).
func TestBearerCaptureIgnoresEmptyAuth(t *testing.T) {
	c := newBearerCapture()

	c.onRequest("req-4", "https://portaldeservicos.pdpj.jus.br/api/v2/processos/abc")
	c.onExtraInfo("req-4", map[string]any{"Authorization": "   "})

	if _, ok := c.bearer(); ok {
		t.Fatal("expected no bearer when Authorization is blank")
	}
}
