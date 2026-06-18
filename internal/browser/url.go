package browser

import (
	"strings"

	"github.com/chromedp/cdproto/page"
)

// mainFrameURLFromEvent extracts the navigated URL from a page.EventFrameNavigated
// when, and only when, it describes the MAIN frame: a frame with an empty
// ParentID. Sub-frames (iframes, service-worker-driven children of type "other"
// the SSO spins up) have a non-empty ParentID and are ignored, so the passively
// tracked URL always reflects the top document the operator is actually on.
//
// It also rejects blank/non-navigable URLs (empty, about:blank, chrome://,
// devtools://) via isRealURL so the tracker never records a placeholder that
// would masquerade as progress. ok=false means "do not update the tracked URL".
//
// This pure extraction is the heart of the passive URL strategy that replaces
// the active chromedp.Location read which failed with "invalid context" during
// the SSO redirect chain. It is unit-tested directly.
func mainFrameURLFromEvent(ev *page.EventFrameNavigated) (string, bool) {
	if ev == nil || ev.Frame == nil {
		return "", false
	}
	if ev.Frame.ParentID != "" {
		return "", false // sub-frame; not the top document
	}
	url := strings.TrimSpace(ev.Frame.URL)
	if !isRealURL(url) {
		return "", false
	}
	return url, true
}

// isAuthenticatedURL reports whether cur indicates the login has completed: the
// browser left the SSO host for jus.br or reached portaldeservicos. A URL still
// on ssoHost is never authenticated, even though the SSO login URL embeds
// redirect_uri=https://www.jus.br as a query parameter -- matching on the host
// having left ssoHost (rather than a bare "www.jus.br" substring) is what keeps
// that embedded redirect_uri from being mistaken for success.
func isAuthenticatedURL(cur string) bool {
	if cur == "" {
		return false
	}
	if strings.Contains(cur, ssoHost) {
		return false
	}
	return strings.Contains(cur, "www.jus.br") ||
		strings.Contains(cur, "portaldeservicos.pdpj.jus.br")
}

// isConfigureTOTPURL reports whether cur is the Keycloak CONFIGURE_TOTP
// required-action page (the realm demands enrolling a new authenticator before
// the login can finish). It keys on the configureTOTPMarker token Keycloak puts
// in the URL, observed live as
// .../login-actions/required-action?execution=CONFIGURE_TOTP&client_id=jusbr.
func isConfigureTOTPURL(cur string) bool {
	return strings.Contains(cur, configureTOTPMarker)
}

// isGovBrURL reports whether cur bounced to gov.br, which means the PJeOffice
// certificate flow failed and the jus.br login must be restarted.
func isGovBrURL(cur string) bool {
	return strings.Contains(cur, "sso.acesso.gov.br")
}

// shouldAttemptTOTPEnroll decides whether the polling loop should run the
// (target-dependent, retrying) enrollment step for cur. Enrollment is attempted
// only on a CONFIGURE_TOTP page that has NOT already been enrolled this run.
// The alreadyEnrolled guard is load-bearing: without it, after a successful
// enroll the loop could re-enter enrollTOTPRobust while the tracked URL still
// shows CONFIGURE_TOTP (the post-submit navigation has not landed yet), and that
// wrapper would spin its full retry window and then fail falsely even though the
// enrollment already succeeded.
func shouldAttemptTOTPEnroll(cur string, alreadyEnrolled bool) bool {
	return isConfigureTOTPURL(cur) && !alreadyEnrolled
}
