package browser

import (
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
)

// TestMainFrameURLFromEventAcceptsMainFrame verifies the core of the passive URL
// tracker: a page.EventFrameNavigated for the MAIN frame (empty ParentID)
// carrying a real URL yields that URL with ok=true. This is the event the
// awaitAuthenticated loop now consumes instead of an active chromedp.Location
// read, so it must extract the navigated URL faithfully.
func TestMainFrameURLFromEventAcceptsMainFrame(t *testing.T) {
	ev := &page.EventFrameNavigated{
		Frame: &cdp.Frame{
			ID:  "main",
			URL: "https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/required-action?execution=CONFIGURE_TOTP",
		},
	}
	got, ok := mainFrameURLFromEvent(ev)
	if !ok {
		t.Fatal("expected main-frame navigation to be accepted, got ok=false")
	}
	want := ev.Frame.URL
	if got != want {
		t.Fatalf("mainFrameURLFromEvent = %q, want %q", got, want)
	}
}

// TestMainFrameURLFromEventRejectsSubframe verifies that navigations of a SUB
// frame (non-empty ParentID: iframes, the SSO's service-worker-driven children)
// are ignored, so the tracked URL only ever reflects the top document the user
// is actually on. Tracking a subframe URL would make the loop chase the wrong
// document and miss CONFIGURE_TOTP on the real page.
func TestMainFrameURLFromEventRejectsSubframe(t *testing.T) {
	ev := &page.EventFrameNavigated{
		Frame: &cdp.Frame{
			ID:       "child",
			ParentID: "main",
			URL:      "https://sso.cloud.pje.jus.br/iframe.html",
		},
	}
	if got, ok := mainFrameURLFromEvent(ev); ok {
		t.Fatalf("expected sub-frame navigation to be rejected, got %q ok=true", got)
	}
}

// TestMainFrameURLFromEventRejectsBlankAndNil verifies the edge cases: a nil
// event, a nil frame, and a main-frame navigation to a blank/non-navigable URL
// must all be rejected so the tracker never records a placeholder that would
// look like progress.
func TestMainFrameURLFromEventRejectsBlankAndNil(t *testing.T) {
	cases := []struct {
		name string
		ev   *page.EventFrameNavigated
	}{
		{"nil event", nil},
		{"nil frame", &page.EventFrameNavigated{Frame: nil}},
		{"about:blank main frame", &page.EventFrameNavigated{Frame: &cdp.Frame{URL: "about:blank"}}},
		{"empty URL main frame", &page.EventFrameNavigated{Frame: &cdp.Frame{URL: ""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := mainFrameURLFromEvent(tc.ev); ok {
				t.Fatalf("expected rejection, got %q ok=true", got)
			}
		})
	}
}

// TestIsAuthenticatedURL verifies the success detector used to leave the polling
// loop: a URL that reached jus.br or portaldeservicos counts as authenticated,
// while any URL still on the SSO host does NOT -- even one that merely contains
// the www.jus.br redirect_uri as a query param (the SSO login URL embeds
// redirect_uri=https://www.jus.br, which must not be mistaken for success).
func TestIsAuthenticatedURL(t *testing.T) {
	authed := []string{
		"https://www.jus.br/",
		"https://www.jus.br/#code=abc",
		"https://portaldeservicos.pdpj.jus.br/consulta-processual",
	}
	for _, u := range authed {
		if !isAuthenticatedURL(u) {
			t.Fatalf("isAuthenticatedURL(%q) = false, want true", u)
		}
	}

	notAuthed := []string{
		"https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth?client_id=jusbr&redirect_uri=https://www.jus.br&response_type=code",
		"https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/required-action?execution=CONFIGURE_TOTP",
		"",
	}
	for _, u := range notAuthed {
		if isAuthenticatedURL(u) {
			t.Fatalf("isAuthenticatedURL(%q) = true, want false (still on SSO)", u)
		}
	}
}

// TestIsConfigureTOTPURL verifies the enrollment detector: the live SSO sends
// the operator to .../login-actions/required-action?execution=CONFIGURE_TOTP,
// which must be recognized, while a plain SSO auth URL must not be.
func TestIsConfigureTOTPURL(t *testing.T) {
	if !isConfigureTOTPURL("https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/required-action?execution=CONFIGURE_TOTP&client_id=jusbr") {
		t.Fatal("isConfigureTOTPURL did not recognize the CONFIGURE_TOTP required-action URL")
	}
	if isConfigureTOTPURL("https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth") {
		t.Fatal("isConfigureTOTPURL matched a plain auth URL")
	}
}

// TestIsGovBrURL verifies detection of the gov.br bounce that means the
// PJeOffice certificate flow failed and the login must be restarted.
func TestIsGovBrURL(t *testing.T) {
	if !isGovBrURL("https://sso.acesso.gov.br/login") {
		t.Fatal("isGovBrURL did not recognize the gov.br host")
	}
	if isGovBrURL("https://sso.cloud.pje.jus.br/auth") {
		t.Fatal("isGovBrURL matched the pje SSO host")
	}
}

// TestShouldAttemptTOTPEnroll verifies the guard that gates the retrying
// enrollment step. Enrollment must be attempted on a fresh CONFIGURE_TOTP page,
// but NOT once enrollment already succeeded this run (otherwise the loop would
// re-enter the retry wrapper while the post-submit navigation is still in flight
// and fail falsely), and NOT on a non-CONFIGURE_TOTP URL.
func TestShouldAttemptTOTPEnroll(t *testing.T) {
	const totpURL = "https://sso.cloud.pje.jus.br/auth/realms/pje/login-actions/required-action?execution=CONFIGURE_TOTP"
	const plainURL = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth"

	if !shouldAttemptTOTPEnroll(totpURL, false) {
		t.Fatal("expected enrollment attempt on a fresh CONFIGURE_TOTP page")
	}
	if shouldAttemptTOTPEnroll(totpURL, true) {
		t.Fatal("must NOT re-attempt enrollment once already enrolled this run")
	}
	if shouldAttemptTOTPEnroll(plainURL, false) {
		t.Fatal("must NOT attempt enrollment on a non-CONFIGURE_TOTP URL")
	}
}
