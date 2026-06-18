package browser

import (
	"errors"
	"testing"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// TestPickActiveTargetPrefersProgressedPage verifies the core recovery
// behavior: when autenticar() spawns or swaps the page target, we must re-bind
// to the page that has progressed PAST the SSO host (the post-login tab),
// preferring it over a page still sitting on the SSO login host and over any
// worker/iframe target. CDP's Target.getTargets does not contract an ordering,
// so the pick must not depend on slice position: the SSO page is listed last
// here on purpose.
func TestPickActiveTargetPrefersProgressedPage(t *testing.T) {
	infos := []*target.Info{
		{TargetID: "t-service", Type: "service_worker", URL: "https://sso.cloud.pje.jus.br/sw.js"},
		{TargetID: "t-progressed", Type: "page", URL: "https://www.jus.br/"},
		{TargetID: "t-sso", Type: "page", URL: "https://sso.cloud.pje.jus.br/auth"},
	}

	id, ok := pickActiveTarget(infos)
	if !ok {
		t.Fatal("expected a page target to be picked, got none")
	}
	if id != target.ID("t-progressed") {
		t.Fatalf("picked %q, want the progressed page target t-progressed", id)
	}
}

// TestPickActiveTargetUsesSSOPageWhenNoneProgressed verifies that while every
// page is still on the SSO host we re-bind to one of them (a real-URL page)
// rather than reporting nothing, so the polling loop continues against a live
// target.
func TestPickActiveTargetUsesSSOPageWhenNoneProgressed(t *testing.T) {
	infos := []*target.Info{
		{TargetID: "t-worker", Type: "service_worker", URL: "https://sso.cloud.pje.jus.br/sw.js"},
		{TargetID: "t-sso", Type: "page", URL: "https://sso.cloud.pje.jus.br/auth"},
	}

	id, ok := pickActiveTarget(infos)
	if !ok {
		t.Fatal("expected the SSO page target to be picked, got none")
	}
	if id != target.ID("t-sso") {
		t.Fatalf("picked %q, want t-sso", id)
	}
}

// TestPickActiveTargetSkipsBlankWhenBetterExists verifies that an about:blank
// (or empty-URL) page target is not chosen when a real page target is present,
// because re-binding to about:blank would just re-trigger the invalid-context /
// dead-poll loop without making progress.
func TestPickActiveTargetSkipsBlankWhenBetterExists(t *testing.T) {
	infos := []*target.Info{
		{TargetID: "t-real", Type: "page", URL: "https://sso.cloud.pje.jus.br/auth"},
		{TargetID: "t-blank", Type: "page", URL: "about:blank"},
		{TargetID: "t-empty", Type: "page", URL: ""},
	}

	id, ok := pickActiveTarget(infos)
	if !ok {
		t.Fatal("expected the real page target to be picked, got none")
	}
	if id != target.ID("t-real") {
		t.Fatalf("picked %q, want the real page target t-real", id)
	}
}

// TestPickActiveTargetFallsBackToBlankWhenOnlyOption verifies that when the only
// page target is about:blank we still return it (recovery must keep a live
// target to poll rather than give up before the deadline).
func TestPickActiveTargetFallsBackToBlankWhenOnlyOption(t *testing.T) {
	infos := []*target.Info{
		{TargetID: "t-worker", Type: "service_worker", URL: "https://x/sw.js"},
		{TargetID: "t-blank", Type: "page", URL: "about:blank"},
	}

	id, ok := pickActiveTarget(infos)
	if !ok {
		t.Fatal("expected the only page target to be picked as a fallback, got none")
	}
	if id != target.ID("t-blank") {
		t.Fatalf("picked %q, want fallback to t-blank", id)
	}
}

// TestPickActiveTargetNoPageTargets verifies that with no page-type target at
// all we report ok=false (the caller must keep retrying until the deadline, not
// bind to a non-page target).
func TestPickActiveTargetNoPageTargets(t *testing.T) {
	infos := []*target.Info{
		{TargetID: "t-worker", Type: "service_worker", URL: "https://x/sw.js"},
		{TargetID: "t-browser", Type: "browser", URL: ""},
	}

	if id, ok := pickActiveTarget(infos); ok {
		t.Fatalf("expected no page target, got %q", id)
	}
}

// TestPickActiveTargetEmpty verifies the empty-list edge: no targets means no
// pick (e.g. the very moment after a crash, before Chrome re-creates a tab).
func TestPickActiveTargetEmpty(t *testing.T) {
	if id, ok := pickActiveTarget(nil); ok {
		t.Fatalf("expected no pick from empty target list, got %q", id)
	}
}

// TestIsInvalidContext verifies that the recovery trigger recognizes chromedp's
// ErrInvalidContext (the exact error observed in the e2e: the taskCtx target was
// destroyed by autenticar()), including when it is wrapped, while not treating
// unrelated errors as recoverable.
func TestIsInvalidContext(t *testing.T) {
	if !isInvalidContext(chromedp.ErrInvalidContext) {
		t.Fatal("expected ErrInvalidContext to be recognized")
	}
	wrapped := errors.New("browser: read current URL: " + chromedp.ErrInvalidContext.Error())
	// A plain wrap by string must NOT match; only real error wrapping counts.
	if isInvalidContext(wrapped) {
		t.Fatal("string-only lookalike must not be treated as invalid context")
	}
	if isInvalidContext(errors.New("some other error")) {
		t.Fatal("unrelated error must not be treated as invalid context")
	}
	if isInvalidContext(nil) {
		t.Fatal("nil must not be treated as invalid context")
	}
}
