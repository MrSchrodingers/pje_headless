package browser

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// ssoHost is the SSO login host. A page target still on this host has not yet
// completed authentication; a page that has left it is the post-login tab we
// want to follow.
const ssoHost = "sso.cloud.pje.jus.br"

// pickActiveTarget selects the page target to (re-)bind a chromedp context to
// after the original tab's target was destroyed or replaced by autenticar()
// (the SSO flow opens/swaps a tab, which invalidates the context bound to the
// initial target).
//
// CDP's Target.getTargets does not contract an ordering, so selection must not
// depend on slice position. Priority, highest first:
//  1. A page target that has progressed PAST the SSO host (a real URL not on
//     ssoHost) -- this is the post-login tab the flow opened/redirected to.
//  2. Any page target with a real, non-blank URL (still on the SSO host).
//  3. Any page target at all, even about:blank, so the caller keeps a live
//     target to poll instead of giving up before the deadline.
//
// Only "page" targets are eligible; workers, iframes, the browser target and
// devtools targets cannot drive the login. If there is no page target at all,
// ok=false tells the caller to retry until the deadline.
func pickActiveTarget(infos []*target.Info) (target.ID, bool) {
	var realURL, anyPage target.ID
	var haveReal, haveAny bool
	for _, info := range infos {
		if info == nil || info.Type != "page" {
			continue
		}
		if !haveAny {
			anyPage, haveAny = info.TargetID, true
		}
		if isRealURL(info.URL) {
			if !strings.Contains(info.URL, ssoHost) {
				return info.TargetID, true // progressed past SSO: best pick
			}
			if !haveReal {
				realURL, haveReal = info.TargetID, true
			}
		}
	}
	if haveReal {
		return realURL, true
	}
	if haveAny {
		return anyPage, true
	}
	return "", false
}

// isRealURL reports whether u is a navigable page URL rather than a blank/empty
// placeholder that would not advance the SSO flow.
func isRealURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	if u == "about:blank" || strings.HasPrefix(u, "chrome://") || strings.HasPrefix(u, "devtools://") {
		return false
	}
	return true
}

// attachBearerListener wires CDP Network events on ctx into capture, reading the
// URL from requestWillBeSent and the raw Authorization header from
// requestWillBeSentExtraInfo, correlated by RequestID. It is attached both to
// the initial page context and to every re-bound context so bearer capture
// survives a target swap.
func attachBearerListener(ctx context.Context, capture *bearerCapture) {
	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			if e.Request != nil {
				capture.onRequest(string(e.RequestID), e.Request.URL)
			}
		case *network.EventRequestWillBeSentExtraInfo:
			capture.onExtraInfo(string(e.RequestID), map[string]any(e.Headers))
		}
	})
}

// isInvalidContext reports whether err is chromedp's ErrInvalidContext, the
// exact error surfaced when the target backing the active context has been
// destroyed (observed in the e2e right after the certificate click, when
// autenticar() swaps the page target). It uses errors.Is so wrapped errors are
// detected, but a mere string lookalike is not.
func isInvalidContext(err error) bool {
	return err != nil && errors.Is(err, chromedp.ErrInvalidContext)
}

// session owns the currently active chromedp page context and knows how to
// re-bind to a fresh page target when the active one dies (the Go equivalent of
// the Python reference's switch_to_new_tab_if_any). It also tracks the current
// main-frame URL PASSIVELY: a page.EventFrameNavigated listener feeds
// onFrameNavigated, and the polling loop consults url() instead of issuing an
// active chromedp.Location read. That active read was the source of the observed
// "invalid context" failure during the SSO redirect chain; replacing it with the
// event stream removes that failure point entirely.
//
// The browser context (allocator + Browser) is shared across all page contexts
// derived from root, so chromedp.Targets and a re-bound context keep working
// even after the original page target is destroyed.
type session struct {
	root    context.Context // a chromedp context whose Browser stays alive
	ctx     context.Context // the currently active page context
	cancel  context.CancelFunc
	capture *bearerCapture
	boundID target.ID

	// urlMu guards lastURL, which is written by the CDP event goroutine
	// (onFrameNavigated, fed by the page.EventFrameNavigated listener) and read
	// by the polling loop (url()). This passive tracking replaces the active
	// chromedp.Location read that failed with "invalid context" during the SSO
	// redirect chain.
	urlMu   sync.Mutex
	lastURL string
}

// onFrameNavigated records the URL of a MAIN-frame navigation, ignoring
// sub-frames and blank URLs (see mainFrameURLFromEvent). It is called from the
// CDP event goroutine via the page.EventFrameNavigated listener and is safe for
// concurrent use with url().
func (s *session) onFrameNavigated(ev *page.EventFrameNavigated) {
	u, ok := mainFrameURLFromEvent(ev)
	if !ok {
		return
	}
	s.urlMu.Lock()
	s.lastURL = u
	s.urlMu.Unlock()
}

// url returns the last observed main-frame URL, or "" if no main-frame
// navigation has been observed yet. The polling loop consults this passively
// instead of issuing an active chromedp.Location read.
func (s *session) url() string {
	s.urlMu.Lock()
	defer s.urlMu.Unlock()
	return s.lastURL
}

// attachFrameListener wires the page.EventFrameNavigated stream on ctx into the
// session's passive URL tracker, so the tracked URL survives target swaps the
// same way bearer capture does. The Page domain must be enabled on ctx for these
// events to fire (see page.Enable() in Login and rebind).
func attachFrameListener(ctx context.Context, s *session) {
	chromedp.ListenTarget(ctx, func(ev any) {
		if e, ok := ev.(*page.EventFrameNavigated); ok {
			s.onFrameNavigated(e)
		}
	})
}

// newSession adopts the initial page context (already created and run) as the
// active context and records the capture to re-attach after a rebind.
func newSession(root, initial context.Context, capture *bearerCapture) *session {
	return &session{
		root:    root,
		ctx:     initial,
		capture: capture,
	}
}

// active returns the context to run actions against.
func (s *session) active() context.Context { return s.ctx }

// rebind re-acquires the most recent live page target and binds a new chromedp
// context to it, re-attaching the network listener so bearer capture survives
// the target swap. It returns an error only on a hard failure (the browser
// itself is gone); a transient "no page target yet" yields rebound=false with a
// nil error so the caller can back off and retry within the deadline.
func (s *session) rebind() (rebound bool, err error) {
	infos, err := chromedp.Targets(s.root)
	if err != nil {
		return false, fmt.Errorf("browser: list targets for rebind: %w", err)
	}
	id, ok := pickActiveTarget(infos)
	if !ok {
		return false, nil // no page target yet; caller retries
	}
	if id == s.boundID && s.boundID != "" {
		// Already bound to this exact target; nothing new to attach to.
		return false, nil
	}

	newCtx, newCancel := chromedp.NewContext(s.root, chromedp.WithTargetID(id))
	// Force attachment to the chosen target before we adopt it, so a stale
	// pick fails here instead of later inside the polling loop. The Page domain
	// is enabled so page.EventFrameNavigated keeps feeding the passive URL
	// tracker on the re-bound target.
	if runErr := chromedp.Run(newCtx, network.Enable(), page.Enable()); runErr != nil {
		newCancel()
		if isInvalidContext(runErr) {
			return false, nil // the picked target died meanwhile; retry
		}
		return false, fmt.Errorf("browser: attach to target %s: %w", id, runErr)
	}

	if s.capture != nil {
		attachBearerListener(newCtx, s.capture)
	}
	attachFrameListener(newCtx, s)

	if s.cancel != nil {
		s.cancel()
	}
	s.ctx = newCtx
	s.cancel = newCancel
	s.boundID = id
	return true, nil
}

// close releases any context this session created during rebinds. The initial
// context is owned by the caller (Login) and is not cancelled here.
func (s *session) close() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}
