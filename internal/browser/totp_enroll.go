package browser

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// configureTOTPMarker is the query-string token Keycloak puts in the URL when a
// realm requires the user to enroll a TOTP authenticator (required-action
// CONFIGURE_TOTP) before the login can complete. Observed live as
// .../login-actions/required-action?execution=CONFIGURE_TOTP&client_id=jusbr.
const configureTOTPMarker = "CONFIGURE_TOTP"

// totpDeviceLabel is the device name written into the Keycloak userLabel field
// when enrolling. It identifies this automated enrollment in the account's
// authenticator list.
const totpDeviceLabel = "pje-headless-robot"

// totpSecretSelectors lists, for error messages, the page locations this package
// reads the enrollment secret from, in priority order. Kept in sync with the
// extraction JS in readTOTPSecretCandidates so a failure names exactly what was
// tried. The hidden totpSecret input (the raw shared key) is the authoritative
// source on jus.br and comes first; the visible #kc-totp-secret-key span (the
// base32 display) is the fallback.
var totpSecretSelectors = []string{
	"[name=totpSecret] / #totpSecret (raw key)",
	"#kc-totp-secret-key (base32 span)",
}

// totpSecretWaitSelectors returns the CSS selectors the enroll step waits on, in
// priority order, to confirm the freshly navigated CONFIGURE_TOTP DOM is ready
// before it reads the secret. The hidden totpSecret input is the authoritative,
// reliably-present source on jus.br (it carries the raw shared key), so it is the
// primary readiness signal and is tried first; the visible #kc-totp-secret-key
// span (the base32 display) is the fallback, since live runs showed it can be
// empty. Each entry is a valid DOM.querySelector string. Reading the secret
// before one of these exists is the observed "invalid context"/empty-read failure
// this wait guards against. WaitReady only requires the node to exist in the DOM
// (not to be visible), so it is satisfied by the hidden input.
func totpSecretWaitSelectors() []string {
	return []string{
		"#totpSecret, [name=totpSecret]",
		"#kc-totp-secret-key",
	}
}

// chooseTOTPSecret derives the base32 TOTP secret from the two candidates the
// Keycloak login-config-totp.ftl page exposes: the value of the hidden totpSecret
// input (hiddenValue) and the textContent of <span id="kc-totp-secret-key">
// (spanText).
//
// Keycloak's hidden totpSecret holds the RAW shared key -- HmacOTP.generateSecret
// returns a random a-zA-Z0-9 string, and the server validates the submitted code
// with secret.getBytes(), while the QR/authenticator secret is
// Base32.encode(totpSecret.getBytes()). So the literal bytes of hiddenValue ARE
// the HMAC key, and the base32 form totpNow needs (and that future logins persist
// as PJE_2FA_TOTP_SECRET) is base32(hiddenValue bytes). The hidden field is
// reliably present and unambiguous, so it is preferred and base32-ENCODED here.
//
// The visible span already holds the base32 form (totpSecretEncoded); it is used
// only when the hidden field is absent, and only if it actually decodes as base32
// -- jus.br has been observed rendering an empty or non-base32 span, which must
// not be enrolled blindly. When neither candidate yields a usable secret the
// function fails loudly (naming the sources tried) rather than enrolling a blank
// or malformed code.
func chooseTOTPSecret(spanText, hiddenValue string) (string, error) {
	if raw := strings.TrimSpace(hiddenValue); raw != "" {
		return base32.StdEncoding.EncodeToString([]byte(raw)), nil
	}
	if span := normalizeBase32Secret(spanText); span != "" {
		if _, err := base32.StdEncoding.DecodeString(span); err == nil {
			return span, nil
		}
	}
	return "", fmt.Errorf(
		"browser: CONFIGURE_TOTP page has no usable secret (tried %s)",
		strings.Join(totpSecretSelectors, ", "),
	)
}

// maybeEnrollTOTP handles the Keycloak CONFIGURE_TOTP required-action page. The
// detection upstream is passive (URL from page.EventFrameNavigated), so by the
// time this runs the CONFIGURE_TOTP target has just navigated and the polling
// loop's context points at the dead pre-navigation target. This function therefore
// REBINDS to the live page target first, WAITS for the enroll DOM to be ready, then
// reads the freshly generated enrollment secret, computes the current code, fills
// the code and device-label fields, and submits the form -- all on the rebound
// context. It returns true when it submitted the enrollment (so the caller backs
// off and lets awaitAuthenticated keep polling), and (false, nil) both when the
// current page is not a CONFIGURE_TOTP page and on a transient invalid-context /
// not-yet-ready DOM (so enrollTOTPRobust rebinds and retries within its window).
// Each sub-step is logged at INFO so a live run is never silent about where it stalls.
//
// Unlike maybeHandle2FA (which needs a pre-shared secret to type an existing
// device's code), enrollment reads the secret the server just minted from the
// page itself; no PJE_2FA_TOTP_SECRET is required. The minted secret is the
// deliverable: it is logged at INFO so the operator can persist it for future
// logins. This is the one place a secret is intentionally logged.
func (b *Browser) maybeEnrollTOTP(sess *session, cur string, enrolled *bool) (bool, error) {
	if *enrolled {
		return false, nil
	}
	if !strings.Contains(cur, configureTOTPMarker) {
		return false, nil
	}

	// The CONFIGURE_TOTP target just navigated; the context the polling loop was
	// using points at the dead pre-navigation target. REBIND to the live page
	// target before any Evaluate, so every active enroll Action below runs in a
	// valid execution context. rebound=false (no new target yet, or already bound)
	// is not fatal: we proceed against the current active context and let the
	// outer retry rebind again on transient invalid-context.
	if rebound, err := sess.rebind(); err != nil {
		return false, err
	} else if rebound {
		b.log.Info("CONFIGURE_TOTP: rebound to live target")
	}
	ctx := sess.active()

	// Wait for the enroll DOM to exist before reading. WaitReady/WaitVisible block
	// until the element appears OR the context deadline fires, so the wait runs on
	// a child context with its own short deadline: a missing element returns from
	// the wait quickly (letting the outer window rebind/retry) instead of blocking
	// the whole enroll window on one stale target.
	if err := waitTOTPSecretReady(ctx); err != nil {
		if isInvalidContext(err) {
			// Target swapped while waiting; let the outer loop rebind and retry.
			return false, nil
		}
		// Element never appeared on this target within the per-attempt wait; not a
		// hard failure, the outer window rebinds and retries.
		return false, nil
	}
	b.log.Info("CONFIGURE_TOTP: secret element visible")

	span, hidden, err := readTOTPSecretCandidates(ctx)
	if err != nil {
		if isInvalidContext(err) {
			// Target swapped while reading; let the outer loop rebind and retry.
			return false, nil
		}
		return false, fmt.Errorf("browser: read CONFIGURE_TOTP secret: %w", err)
	}

	secret, err := chooseTOTPSecret(span, hidden)
	if err != nil {
		return false, err
	}
	// The minted secret is the deliverable: the operator MUST persist it to log
	// in again without re-enrolling. This is the single intentional secret log.
	b.log.Info("CONFIGURE_TOTP: secret read", "PJE_2FA_TOTP_SECRET", secret)

	code, err := totpNow(secret)
	if err != nil {
		return false, fmt.Errorf("browser: generate TOTP for enrollment: %w", err)
	}
	b.log.Info("CONFIGURE_TOTP: enrollment code generated")

	ok, err := submitTOTPEnrollment(ctx, code)
	if err != nil {
		if isInvalidContext(err) {
			return false, nil
		}
		return false, fmt.Errorf("browser: submit CONFIGURE_TOTP: %w", err)
	}
	if !ok {
		// The secret element was present but the code/submit field was not yet on
		// this target; let the outer window rebind and retry instead of failing the
		// whole login on a transient half-rendered form.
		return false, nil
	}

	*enrolled = true
	b.log.Info("CONFIGURE_TOTP: enrollment form submitted")
	return true, nil
}

// totpSecretWaitTimeout bounds the per-attempt wait for the enroll DOM. It is the
// child-context deadline given to waitTOTPSecretReady so a stale or half-rendered
// target returns from the wait quickly, letting enrollTOTPRobust rebind to a fresh
// target rather than blocking the whole enroll window on one dead context.
const totpSecretWaitTimeout = 8 * time.Second

// waitTOTPSecretReady blocks until the CONFIGURE_TOTP enroll DOM is ready on ctx:
// first the document body, then the secret element identified by
// totpSecretWaitSelectors (the visible span, then the hidden-input fallback). It
// runs on child contexts each bounded by totpSecretWaitTimeout so a target where
// the element never appears returns promptly with a deadline error instead of
// hanging until the outer window expires.
//
// chromedp.WaitReady blocks until its element exists OR the context deadline
// fires, so each selector gets its OWN bounded child context: a span that never
// renders does not consume the whole budget and starve the hidden-input fallback.
// It returns nil as soon as any selector is ready, and propagates invalid-context
// immediately so the caller can rebind.
func waitTOTPSecretReady(ctx context.Context) error {
	if err := waitReadyBounded(ctx, "body"); err != nil {
		return err
	}

	var lastErr error
	for _, sel := range totpSecretWaitSelectors() {
		err := waitReadyBounded(ctx, sel)
		if err == nil {
			return nil
		}
		if isInvalidContext(err) {
			return err // dead target: stop and let the caller rebind
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("browser: no CONFIGURE_TOTP secret selector to wait on")
	}
	return lastErr
}

// waitReadyBounded runs chromedp.WaitReady(sel) on a child context bounded by
// totpSecretWaitTimeout so the wait cannot block past the per-attempt budget.
func waitReadyBounded(ctx context.Context, sel string) error {
	waitCtx, cancel := context.WithTimeout(ctx, totpSecretWaitTimeout)
	defer cancel()
	// chromedp.Run injects the page target as the CDP executor into the context
	// for the duration of the action; calling Action.Do(ctx) directly panics with
	// a nil cdp.Executor when ctx is a bare session context (the rebound
	// sess.active() context carries the *chromedp.Context value but no executor
	// outside a Run). Run is the canonical entry point and matches rebind() and
	// captureBearer() elsewhere in this package.
	return chromedp.Run(waitCtx, chromedp.WaitReady(sel, chromedp.ByQuery))
}

// readTOTPSecretCandidates extracts both secret candidates from the page in one
// evaluation: the textContent of #kc-totp-secret-key and the value of the hidden
// totpSecret input. Either may be empty; chooseTOTPSecret decides which to use.
func readTOTPSecretCandidates(ctx context.Context) (span, hidden string, err error) {
	const js = `(function(){
		var spanEl = document.querySelector("#kc-totp-secret-key");
		var hiddenEl = document.querySelector("[name=totpSecret], #totpSecret");
		return {
			span: spanEl ? (spanEl.textContent || "") : "",
			hidden: hiddenEl ? (hiddenEl.value || "") : ""
		};
	})()`
	var out struct {
		Span   string `json:"span"`
		Hidden string `json:"hidden"`
	}
	if evalErr := chromedp.Run(ctx, chromedp.Evaluate(js, &out)); evalErr != nil {
		return "", "", evalErr
	}
	return out.Span, out.Hidden, nil
}

// submitTOTPEnrollment fills the Keycloak code field (#totp / name=totp) with
// code and the device-label field (#userLabel / name=userLabel) with
// totpDeviceLabel, then submits the form. It clicks the submit control when
// present and falls back to form.submit(). It returns true when the code field
// was found and a submit path was taken.
func submitTOTPEnrollment(ctx context.Context, code string) (bool, error) {
	js := `(function(code, label){
		var totp = document.querySelector("#totp, input[name=totp]");
		if(!totp){ return false; }
		totp.value = code;
		totp.dispatchEvent(new Event('input', {bubbles:true}));
		totp.dispatchEvent(new Event('change', {bubbles:true}));

		var userLabel = document.querySelector("#userLabel, input[name=userLabel]");
		if(userLabel){
			userLabel.value = label;
			userLabel.dispatchEvent(new Event('input', {bubbles:true}));
			userLabel.dispatchEvent(new Event('change', {bubbles:true}));
		}

		var btn = document.querySelector("#saveTOTPBtn, input[type=submit], button[type=submit]");
		if(btn){ btn.click(); return true; }
		if(totp.form){ totp.form.submit(); return true; }
		return false;
	})(` + jsString(code) + `, ` + jsString(totpDeviceLabel) + `)`
	var ok bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &ok)); err != nil {
		return false, err
	}
	return ok, nil
}

// enrollTOTPBackoff is the pause after submitting enrollment before the polling
// loop re-reads the URL, giving the SSO time to process the form and redirect.
const enrollTOTPBackoff = 5 * time.Second

// enrollRetryWindow bounds enrollTOTPRobust: once a CONFIGURE_TOTP URL is
// observed, the enroll Actions (rebind to the live target, wait for the enroll
// DOM, read the minted secret, type the code, submit) are retried against a fresh
// live target on transient invalid-context / not-yet-ready DOM until this
// sub-deadline. Widened from 30s to 60s because each attempt now spends time
// waiting for the freshly navigated CONFIGURE_TOTP DOM (totpSecretWaitTimeout per
// selector) before it can read; 30s left too few retries when the first target
// was the dead pre-navigation one. If the secret/form never becomes readable in
// this window, the login fails loudly rather than spinning until the outer
// 3-minute timeout.
const enrollRetryWindow = 60 * time.Second

// enrollRetryBackoff is the pause between enroll attempts inside the retry
// window, giving a swapped target time to settle before the next read.
const enrollRetryBackoff = 1 * time.Second
