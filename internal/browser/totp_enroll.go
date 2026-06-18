package browser

import (
	"context"
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
// extraction JS in enrollTOTP so a failure names exactly what was tried.
var totpSecretSelectors = []string{
	"#kc-totp-secret-key",
	"[name=totpSecret] / #totpSecret",
}

// chooseTOTPSecret selects the enrollment secret from the two candidates the
// Keycloak login-config-totp.ftl page exposes: the visible, space-grouped
// base32 string inside <span id="kc-totp-secret-key"> (spanText) and the raw
// value of the hidden totpSecret input (hiddenValue). The visible span wins when
// non-empty; otherwise the hidden value is used. The chosen candidate is
// normalized (whitespace stripped, upper-cased) so it decodes as base32 and
// drives totpNow.
//
// When neither candidate yields a non-empty secret the function fails with an
// error naming the selectors it tried, because a CONFIGURE_TOTP page with no
// readable secret must stop the flow loudly rather than enroll a blank code.
func chooseTOTPSecret(spanText, hiddenValue string) (string, error) {
	for _, candidate := range []string{spanText, hiddenValue} {
		if normalizeBase32Secret(candidate) != "" {
			return normalizeBase32Secret(candidate), nil
		}
	}
	return "", fmt.Errorf(
		"browser: CONFIGURE_TOTP page has no readable secret (tried %s)",
		strings.Join(totpSecretSelectors, ", "),
	)
}

// maybeEnrollTOTP handles the Keycloak CONFIGURE_TOTP required-action page: it
// reads the freshly generated enrollment secret from the page, computes the
// current code, fills the code and device-label fields, and submits the form so
// the SSO can finish redirecting to jus.br. It returns true when it submitted
// the enrollment (so the caller backs off and lets awaitAuthenticated keep
// polling), false when the current page is not a CONFIGURE_TOTP page.
//
// Unlike maybeHandle2FA (which needs a pre-shared secret to type an existing
// device's code), enrollment reads the secret the server just minted from the
// page itself; no PJE_2FA_TOTP_SECRET is required. The minted secret is the
// deliverable: it is logged at INFO so the operator can persist it for future
// logins. This is the one place a secret is intentionally logged.
func (b *Browser) maybeEnrollTOTP(ctx context.Context, cur string, enrolled *bool) (bool, error) {
	if *enrolled {
		return false, nil
	}
	if !strings.Contains(cur, configureTOTPMarker) {
		return false, nil
	}

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

	code, err := totpNow(secret)
	if err != nil {
		return false, fmt.Errorf("browser: generate TOTP for enrollment: %w", err)
	}

	ok, err := submitTOTPEnrollment(ctx, code)
	if err != nil {
		if isInvalidContext(err) {
			return false, nil
		}
		return false, fmt.Errorf("browser: submit CONFIGURE_TOTP: %w", err)
	}
	if !ok {
		return false, errors.New("browser: CONFIGURE_TOTP page present but the enrollment form could not be filled/submitted")
	}

	*enrolled = true
	// The minted secret is the deliverable: the operator MUST persist it to log
	// in again without re-enrolling. This is the single intentional secret log.
	b.log.Info("TOTP cadastrado", "PJE_2FA_TOTP_SECRET", secret)
	return true, nil
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
	if evalErr := chromedp.Evaluate(js, &out).Do(ctx); evalErr != nil {
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
	if err := chromedp.Evaluate(js, &ok).Do(ctx); err != nil {
		return false, err
	}
	return ok, nil
}

// enrollTOTPBackoff is the pause after submitting enrollment before the polling
// loop re-reads the URL, giving the SSO time to process the form and redirect.
const enrollTOTPBackoff = 5 * time.Second

// enrollRetryWindow bounds enrollTOTPRobust: once a CONFIGURE_TOTP URL is
// observed, the enroll Actions (read the minted secret, type the code, submit)
// are retried against a fresh live target on transient invalid-context until
// this sub-deadline. If the secret/form never becomes readable in this window,
// the login fails loudly rather than spinning until the outer 3-minute timeout.
const enrollRetryWindow = 30 * time.Second

// enrollRetryBackoff is the pause between enroll attempts inside the retry
// window, giving a swapped target time to settle before the next read.
const enrollRetryBackoff = 1 * time.Second
