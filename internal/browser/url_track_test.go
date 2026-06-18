package browser

import (
	"sync"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
)

// TestSessionTracksMainFrameURLPassively verifies the passive URL tracker that
// replaces the failing active chromedp.Location read: feeding the session a
// page.EventFrameNavigated for the MAIN frame updates the URL returned by url(),
// while a sub-frame navigation does NOT clobber it. The session starts with an
// empty tracked URL (no navigation observed yet).
func TestSessionTracksMainFrameURLPassively(t *testing.T) {
	s := &session{}

	if got := s.url(); got != "" {
		t.Fatalf("fresh session url() = %q, want empty", got)
	}

	main := &page.EventFrameNavigated{Frame: &cdp.Frame{
		ID:  "main",
		URL: "https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/required-action?execution=CONFIGURE_TOTP",
	}}
	s.onFrameNavigated(main)
	if got, want := s.url(), main.Frame.URL; got != want {
		t.Fatalf("after main-frame nav, url() = %q, want %q", got, want)
	}

	// A sub-frame navigation must be ignored: the tracked top URL stays put.
	sub := &page.EventFrameNavigated{Frame: &cdp.Frame{
		ID:       "child",
		ParentID: "main",
		URL:      "https://sso.cloud.pje.jus.br/iframe.html",
	}}
	s.onFrameNavigated(sub)
	if got, want := s.url(), main.Frame.URL; got != want {
		t.Fatalf("sub-frame nav clobbered tracked URL: url() = %q, want %q", got, want)
	}

	// A later main-frame navigation (success) advances the tracked URL.
	done := &page.EventFrameNavigated{Frame: &cdp.Frame{
		ID:  "main",
		URL: "https://www.jus.br/",
	}}
	s.onFrameNavigated(done)
	if got, want := s.url(), done.Frame.URL; got != want {
		t.Fatalf("after success nav, url() = %q, want %q", got, want)
	}
}

// TestSessionURLConcurrentAccess verifies the tracker is safe under concurrent
// writes (the CDP event goroutine) and reads (the polling loop). Run with -race
// this would flag an unguarded field; the assertion here is simply that a final
// consistent value is observed without panic or data loss.
func TestSessionURLConcurrentAccess(t *testing.T) {
	s := &session{}
	const finalURL = "https://www.jus.br/"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.onFrameNavigated(&page.EventFrameNavigated{Frame: &cdp.Frame{
				URL: "https://sso.cloud.pje.jus.br/auth",
			}})
			_ = s.url()
		}()
	}
	wg.Wait()

	// Final deterministic write so the assertion is not racy.
	s.onFrameNavigated(&page.EventFrameNavigated{Frame: &cdp.Frame{URL: finalURL}})
	if got := s.url(); got != finalURL {
		t.Fatalf("after concurrent writes, url() = %q, want %q", got, finalURL)
	}
}
