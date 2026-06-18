// Package browser performs the headless jus.br SSO login via chromedp/CDP and
// captures the resulting bearer token. It is a faithful Go port of the proven
// flow in vigia/services/pje_worker.py::_get_bearer_token, with the
// selenium-wire request interception replaced by the native CDP Network domain
// (see capture.go) and the certificate handshake delegated to the local
// pjeoffice.Server (the page's autenticar() callback POSTs to
// http://127.0.0.1:8800/pjeOffice/requisicao/, which this server signs via the
// injected signer.Signer).
//
// The real login can only be validated end-to-end against jus.br on a host with
// Chrome and a valid certificate token. The pure, deterministic pieces (TOTP
// generation and bearer capture) are unit-tested; the orchestration here is
// build-verified only.
package browser

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/MrSchrodingers/pje_headless/internal/pjeoffice"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

const (
	loginURL = "https://sso.cloud.pje.jus.br/auth/realms/pje/protocol/openid-connect/auth" +
		"?client_id=jusbr&scope=openid&redirect_uri=https://www.jus.br&response_type=code"
	consultaURL = "https://portaldeservicos.pdpj.jus.br/consulta-processual"

	// sampleProcesso is the dummy process number typed into the search form to
	// trigger the authenticated /api/v2/processos/ call whose Authorization
	// header carries the bearer token. It mirrors the constant used by the
	// proven Python reference.
	sampleProcesso = "07108025520188020001"

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Config controls the Browser. Zero values fall back to safe defaults.
type Config struct {
	// PJeOfficeBindAddr / PJeOfficePort: where the local signing server listens.
	// The page's autenticar() callback hardcodes 127.0.0.1:8800, so callers
	// should keep these at loopback:8800 unless the page is patched.
	PJeOfficeBindAddr string
	PJeOfficePort     string

	// TOTPSecret is the base32 2FA secret. When empty and the page demands a
	// 2FA code, Login fails with a clear error. Source from PJE_2FA_TOTP_SECRET;
	// never hardcode.
	TOTPSecret string

	// ChromePath optionally overrides the Chrome/Chromium binary path.
	ChromePath string

	// LoginTimeout bounds the whole Login call. Default 4 minutes.
	LoginTimeout time.Duration
}

// Browser drives the headless login. Construct via New.
type Browser struct {
	signer signer.Signer
	cfg    Config
	log    *slog.Logger
	debug  bool // when true, chromedp CDP traffic is logged to stderr
}

// New creates a Browser that signs the certificate handshake with s. The
// signer must be safe for concurrent use (the pjeoffice.Server calls it from
// its request goroutine).
func New(s signer.Signer, cfg Config, log *slog.Logger) *Browser {
	if cfg.PJeOfficeBindAddr == "" {
		cfg.PJeOfficeBindAddr = "127.0.0.1"
	}
	if cfg.PJeOfficePort == "" {
		cfg.PJeOfficePort = "8800"
	}
	if cfg.LoginTimeout == 0 {
		cfg.LoginTimeout = 4 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Browser{
		signer: s,
		cfg:    cfg,
		log:    log,
		debug:  os.Getenv(envChromedpDebug) != "",
	}
}

// Login performs the full headless SSO flow and returns the captured bearer
// token (the full "Bearer <jwt>" header value). It:
//  1. Starts the local pjeoffice.Server on loopback so the page's certificate
//     handshake can be signed.
//  2. Launches headless Chrome, navigates to the SSO login page, and triggers
//     the certificate authentication (autenticar()).
//  3. Handles optional 2FA (TOTP) and SSO redirects until reaching jus.br /
//     portaldeservicos.
//  4. Opens the process-consultation page, fires a search, and captures the
//     Authorization header from the /api/v2/processos/ request via CDP.
func (b *Browser) Login(ctx context.Context) (string, error) {
	if b.signer == nil {
		return "", errors.New("browser: nil signer")
	}

	ctx, cancel := context.WithTimeout(ctx, b.cfg.LoginTimeout)
	defer cancel()

	// 1) Local signing server on loopback. The page hardcodes 127.0.0.1:8800.
	stopServer, err := b.startPJeOffice()
	if err != nil {
		return "", fmt.Errorf("browser: start pjeoffice server: %w", err)
	}
	defer stopServer()

	// 2) Headless Chrome.
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, b.allocatorOptions()...)
	defer cancelAlloc()

	taskCtx, cancelTask := chromedp.NewContext(allocCtx, b.contextOptions()...)
	defer cancelTask()

	capture := newBearerCapture()
	b.attachNetworkListener(taskCtx, capture)

	// The certificate click can swap/destroy the initial page target, which
	// invalidates taskCtx. From here on, drive the flow through a session that
	// re-binds to the live page target instead of aborting on invalid-context.
	// The session is created before the initial Run so its passive URL tracker
	// (fed by page.EventFrameNavigated) is listening from the first navigation.
	sess := newSession(taskCtx, taskCtx, capture)
	defer sess.close()
	attachFrameListener(taskCtx, sess)

	if err := chromedp.Run(taskCtx,
		network.Enable(),
		page.Enable(),
		chromedp.Navigate(loginURL),
		b.waitAutenticarReady(),
		b.clickCertLink(),
	); err != nil {
		return "", fmt.Errorf("browser: initial login navigation: %w", err)
	}

	// 3) Drive SSO/2FA until we leave the SSO host.
	if err := b.awaitAuthenticated(sess); err != nil {
		return "", err
	}

	// 4) Open consultation, fire search, capture bearer.
	bearer, err := b.captureBearer(sess, capture)
	if err != nil {
		return "", err
	}
	return bearer, nil
}

// contextOptions returns the chromedp context options. When PJE_CHROMEDP_DEBUG
// is set, it enables WithDebugf/WithErrorf so the raw CDP protocol traffic
// (Target.targetCreated/targetDestroyed, navigation, crashes) is written to
// stderr. This is the instrumentation used to confirm the invalid-context root
// cause and is otherwise a no-op. It writes to stderr directly (not via the
// structured logger) so the verbose protocol dump stays out of the normal log
// stream and is unconditionally visible when debugging.
func (b *Browser) contextOptions() []chromedp.ContextOption {
	if !b.debug {
		return nil
	}
	debugf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[chromedp DEBUG] "+format+"\n", args...)
	}
	errorf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[chromedp ERROR] "+format+"\n", args...)
	}
	return []chromedp.ContextOption{
		chromedp.WithDebugf(debugf),
		chromedp.WithErrorf(errorf),
	}
}

// startPJeOffice starts the signing server on the configured loopback address
// and returns a stop function. The listener is owned here so the lifecycle is
// bounded by Login.
func (b *Browser) startPJeOffice() (func(), error) {
	srv := pjeoffice.NewServer(b.signer, b.cfg.PJeOfficePort, b.cfg.PJeOfficeBindAddr)
	srv.SetLogger(b.log)

	addr := net.JoinHostPort(b.cfg.PJeOfficeBindAddr, b.cfg.PJeOfficePort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil &&
			!errors.Is(serveErr, net.ErrClosed) {
			b.log.Error("pjeoffice server exited", "err", serveErr)
		}
	}()

	return func() { _ = ln.Close() }, nil
}

// allocatorOptions returns the headless Chrome flags matching the proven
// reference: --headless=new, --no-sandbox, --disable-dev-shm-usage,
// --disable-gpu, a desktop window size and a desktop user agent.
func (b *Browser) allocatorOptions() []chromedp.ExecAllocatorOption {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", "new"),
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.DisableGPU,
		chromedp.WindowSize(1920, 1080),
		chromedp.UserAgent(userAgent),
		// O handshake do PJeOffice carrega uma imagem de http://localhost:8800 a
		// partir da pagina HTTPS do SSO. O Chrome (Private/Local Network Access)
		// bloqueia requests publico->loopback ("access the loopback address
		// space") e o handshake morre antes de chegar ao :8800. Desabilitamos as
		// features de PNA/LNA e permitimos conteudo inseguro para o fluxo headless.
		chromedp.Flag("disable-features", "BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults,LocalNetworkAccessChecks"),
		chromedp.Flag("allow-running-insecure-content", true),
	}
	if b.cfg.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(b.cfg.ChromePath))
	}
	return opts
}

// attachNetworkListener wires CDP Network events into the bearerCapture. It
// reads the URL from requestWillBeSent and the raw Authorization header from
// requestWillBeSentExtraInfo (where the Angular app's injected bearer appears),
// correlating them by RequestID. This is the native-CDP replacement for
// selenium-wire's wait_for_request.
func (b *Browser) attachNetworkListener(ctx context.Context, capture *bearerCapture) {
	attachBearerListener(ctx, capture)
}

// waitAutenticarReady blocks until window.autenticar is a function, matching
// the Python reference's wait on typeof window.autenticar === 'function'.
func (b *Browser) waitAutenticarReady() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			var ready bool
			if err := chromedp.Evaluate(
				"typeof window.autenticar === 'function'", &ready,
			).Do(ctx); err == nil && ready {
				// Give the PJeOffice JS a moment to initialize, as in the reference.
				return sleepCtx(ctx, 3*time.Second)
			}
			if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
				return err
			}
		}
		return errors.New("browser: window.autenticar did not become available within 60s")
	})
}

// clickCertLink triggers the "Entrar com Seu certificado digital" link, whose
// onclick attribute calls autenticar('<challenge>'). Firing autenticar() is what
// makes the page POST the certificate handshake to the local pjeoffice server,
// so the click MUST run the inline onclick handler -- a DOM coordinate click
// would race with overlays and is not what the proven Python reference does.
// This is the faithful Go analogue of
// driver.execute_script("arguments[0].click();", cert_link): a single JS click()
// on the anchor, which runs onclick="autenticar('<challenge>')" exactly once
// (firing it twice could double-POST the handshake and break it).
func (b *Browser) clickCertLink() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		const js = `(function(){
			var el = document.querySelector("a[onclick*='autenticar']");
			if(!el){ return false; }
			el.click();
			return true;
		})()`
		var clicked bool
		if err := chromedp.Evaluate(js, &clicked).Do(ctx); err != nil {
			return fmt.Errorf("browser: click cert link: %w", err)
		}
		if !clicked {
			return errors.New("browser: certificate link (autenticar) not found on login page")
		}
		return nil
	})
}

// awaitAuthenticated polls the PASSIVELY tracked main-frame URL until it leaves
// the SSO host (success), or handles the CONFIGURE_TOTP enrollment, optional 2FA
// prompt, gov.br fallback, and certificate retry. The URL is read from
// sess.url() (fed by page.EventFrameNavigated) rather than an active
// chromedp.Location call: that active read was the observed "invalid context"
// failure, caused by autenticar() swapping the page target mid-redirect. When
// the active page context dies, the loop rebinds the session so the event
// listener re-attaches to a live target and the tracker keeps advancing until the
// deadline. Every observed URL change and phase transition is logged at INFO so a
// live run is never silent about where it stalls.
func (b *Browser) awaitAuthenticated(sess *session) error {
	certClickedAt := time.Now()
	deadline := time.Now().Add(3 * time.Minute)
	certRetries := 0
	twoFASubmitted := false
	totpEnrolled := false
	lastLoggedURL := ""

	b.log.Info("awaiting SSO authentication", "timeout", time.Until(deadline).String())

	for time.Now().Before(deadline) {
		select {
		case <-sess.root.Done():
			return sess.root.Err()
		default:
		}

		// Passive read: the URL comes from page.EventFrameNavigated of the main
		// frame (tracked under mutex), so there is no active chromedp.Location
		// read that can fail with "invalid context" during the redirect chain.
		// When the active page target dies, rebind so the listener re-attaches to
		// a live target and keeps feeding the tracker.
		if sess.active().Err() != nil {
			if _, rebindErr := sess.rebind(); rebindErr != nil {
				return rebindErr
			}
		}
		cur := sess.url()
		ctx := sess.active()

		// Log every observed URL change at INFO so the next live run is not blind
		// to where the flow stalls.
		if cur != "" && cur != lastLoggedURL {
			b.log.Info("SSO url", "url", cur)
			lastLoggedURL = cur
		}

		// 1) Success: left the SSO host for jus.br / portaldeservicos.
		if isAuthenticatedURL(cur) {
			b.log.Info("left SSO host; authentication complete", "url", cur)
			return nil
		}

		// 2) Bounced to gov.br -> PJeOffice flow failed; restart login.
		if isGovBrURL(cur) {
			b.log.Warn("redirected to gov.br; restarting jus.br login")
			if err := chromedp.Run(ctx, chromedp.Navigate(loginURL)); err != nil {
				if isInvalidContext(err) {
					continue // target swapped under us; the loop will rebind
				}
				return fmt.Errorf("browser: restart login after gov.br: %w", err)
			}
			if err := sleepCtx(sess.root, 3*time.Second); err != nil {
				return err
			}
			continue
		}

		// 3) CONFIGURE_TOTP required-action? Enroll the authenticator (the
		// account demands registering a new TOTP, not just typing a code). The
		// minted secret is logged at INFO for the operator to persist. The enroll
		// retries on transient invalid-context against a fresh live target.
		if shouldAttemptTOTPEnroll(cur, totpEnrolled) {
			b.log.Info("detected CONFIGURE_TOTP required-action", "url", cur)
			enrolled, err := b.enrollTOTPRobust(sess, cur, &totpEnrolled)
			if err != nil {
				return err
			}
			if enrolled {
				b.log.Info("CONFIGURE_TOTP enrollment submitted")
				if err := sleepCtx(sess.root, enrollTOTPBackoff); err != nil {
					return err
				}
				continue
			}
		}

		// 4) 2FA prompt? Handle it (or fail loudly if no secret).
		handled, err := b.maybeHandle2FA(ctx, cur, certClickedAt, &twoFASubmitted)
		if err != nil {
			return err
		}
		if handled {
			if err := sleepCtx(sess.root, 5*time.Second); err != nil {
				return err
			}
			continue
		}

		// 5) Certificate link visible again -> retry the click (bounded).
		retried, err := b.maybeRetryCert(ctx, &certRetries, &certClickedAt)
		if err != nil {
			return err
		}
		if retried {
			if err := sleepCtx(sess.root, 5*time.Second); err != nil {
				return err
			}
			continue
		}

		if err := sleepCtx(sess.root, 1*time.Second); err != nil {
			return err
		}
	}
	return errors.New("browser: timed out waiting for SSO redirect / 2FA completion")
}

// enrollTOTPRobust drives maybeEnrollTOTP against the session's active page
// target, re-trying on a transient invalid-context error by rebinding to a fresh
// live target until a short sub-deadline. maybeEnrollTOTP already swallows
// invalid-context internally (returning enrolled=false, err=nil); this wrapper
// adds the rebind-and-retry so a target swap mid-enroll does not silently leave
// the form unfilled. A real failure (secret not found, form not submittable)
// propagates immediately.
func (b *Browser) enrollTOTPRobust(sess *session, cur string, enrolled *bool) (bool, error) {
	subDeadline := time.Now().Add(enrollRetryWindow)
	attempt := 0
	for time.Now().Before(subDeadline) {
		attempt++
		ok, err := b.maybeEnrollTOTP(sess.active(), cur, enrolled)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		// Not enrolled and no hard error: either not a CONFIGURE_TOTP page (the
		// caller already checked, so this is a transient invalid-context the
		// enroll swallowed) or the secret/form was not ready yet. Rebind to a
		// live target and retry.
		b.log.Info("CONFIGURE_TOTP enroll attempt did not submit; retrying", "attempt", attempt)
		if _, rebindErr := sess.rebind(); rebindErr != nil {
			return false, rebindErr
		}
		if err := sleepCtx(sess.root, enrollRetryBackoff); err != nil {
			return false, err
		}
	}
	return false, fmt.Errorf(
		"browser: CONFIGURE_TOTP detected but enrollment did not complete within %s (secret/form never became readable)",
		enrollRetryWindow,
	)
}

// maybeHandle2FA detects the 2FA input (txtAcessoCodigo or otp) and, when
// present, submits the TOTP. If the field is present but no TOTPSecret is
// configured, it returns a clear error. Returns true when it submitted a code.
func (b *Browser) maybeHandle2FA(
	ctx context.Context, cur string, certClickedAt time.Time, submitted *bool,
) (bool, error) {
	if *submitted {
		return false, nil
	}

	// Detect a present 2FA field. We treat "present in DOM" as the trigger,
	// matching the reference's fallback that fills a non-visible field after an
	// idle period on the SSO page.
	const detectJS = `(function(){
		var el = document.querySelector("input[name='txtAcessoCodigo'], input[name='otp']");
		return !!el;
	})()`
	var present bool
	if err := chromedp.Evaluate(detectJS, &present).Do(ctx); err != nil {
		return false, nil // transient eval error; let the loop retry
	}
	if !present {
		return false, nil
	}

	// A 2FA field exists. Without a secret we must fail loudly.
	if b.cfg.TOTPSecret == "" {
		return false, errors.New(
			"browser: 2FA exigido mas PJE_2FA_TOTP_SECRET ausente")
	}

	// Only fill once we are confident the prompt is real: either the field is
	// visible, or we have been idle on the SSO page for >60s (reference behavior).
	const visibleJS = `(function(){
		var el = document.querySelector("input[name='txtAcessoCodigo'], input[name='otp']");
		if(!el){ return false; }
		var r = el.getBoundingClientRect();
		return r.width > 0 && r.height > 0;
	})()`
	var visible bool
	_ = chromedp.Evaluate(visibleJS, &visible).Do(ctx)

	idleOnSSO := strings.Contains(cur, "sso.cloud.pje.jus.br") &&
		time.Since(certClickedAt) > 60*time.Second
	if !visible && !idleOnSSO {
		return false, nil
	}

	code, err := totpNow(b.cfg.TOTPSecret)
	if err != nil {
		return false, fmt.Errorf("browser: generate TOTP: %w", err)
	}

	submitJS := `(function(code){
		var el = document.querySelector("input[name='txtAcessoCodigo'], input[name='otp']");
		if(!el){ return false; }
		el.value = code;
		el.dispatchEvent(new Event('input', {bubbles:true}));
		el.dispatchEvent(new Event('change', {bubbles:true}));
		var btn = document.querySelector("#btnEntrar, #kc-login, input[type='submit'], button[type='submit']");
		if(btn){ btn.click(); return true; }
		if(el.form){ el.form.submit(); return true; }
		return false;
	})(` + jsString(code) + `)`
	var ok bool
	if err := chromedp.Evaluate(submitJS, &ok).Do(ctx); err != nil {
		if isInvalidContext(err) {
			// Target swapped during submit; let the outer loop rebind and
			// re-detect rather than failing the whole login.
			return false, nil
		}
		return false, fmt.Errorf("browser: submit 2FA: %w", err)
	}
	if !ok {
		return false, errors.New("browser: 2FA field present but could not submit the code")
	}
	*submitted = true
	b.log.Info("2FA TOTP submitted")
	return true, nil
}

// maybeRetryCert re-clicks the certificate link when it reappears (the SSO
// bounced us back), up to 5 times. Returns true when it re-clicked.
func (b *Browser) maybeRetryCert(
	ctx context.Context, retries *int, certClickedAt *time.Time,
) (bool, error) {
	if *retries >= 5 {
		return false, nil
	}
	const js = `(function(){
		var el = document.querySelector("a[onclick*='autenticar']");
		if(!el){ return false; }
		var r = el.getBoundingClientRect();
		if(r.width === 0 || r.height === 0){ return false; }
		el.click();
		return true;
	})()`
	var clicked bool
	if err := chromedp.Evaluate(js, &clicked).Do(ctx); err != nil {
		return false, nil
	}
	if !clicked {
		return false, nil
	}
	*retries++
	*certClickedAt = time.Now()
	b.log.Warn("certificate link reappeared; re-clicked", "attempt", *retries)
	return true, nil
}

// captureBearer navigates to the consultation page, fires a search, and waits
// for the bearerCapture to receive the Authorization header of the
// /api/v2/processos/ request. It runs against the session's active page target
// and re-binds once if that target was swapped while leaving the SSO flow.
func (b *Browser) captureBearer(sess *session, capture *bearerCapture) (string, error) {
	b.log.Info("opening consulta to capture bearer", "url", consultaURL)
	ctx := sess.active()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(consultaURL),
		b.waitConsultaForm(),
		b.fireSearch(),
	); err != nil {
		if !isInvalidContext(err) {
			return "", fmt.Errorf("browser: open consulta and search: %w", err)
		}
		// The active target died as we left the SSO flow; rebind and retry once.
		if _, rebindErr := sess.rebind(); rebindErr != nil {
			return "", rebindErr
		}
		if err := chromedp.Run(sess.active(),
			chromedp.Navigate(consultaURL),
			b.waitConsultaForm(),
			b.fireSearch(),
		); err != nil {
			return "", fmt.Errorf("browser: open consulta and search after rebind: %w", err)
		}
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if tok, ok := capture.bearer(); ok {
			b.log.Info("bearer token captured")
			return tok, nil
		}
		if err := sleepCtx(sess.root, 250*time.Millisecond); err != nil {
			return "", err
		}
	}
	return "", errors.New("browser: API call intercepted without an Authorization header (no bearer captured)")
}

// waitConsultaForm waits for the process-number input to be present.
func (b *Browser) waitConsultaForm() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			const js = `!!document.querySelector("input[formcontrolname='numeroProcesso']")`
			var ready bool
			if err := chromedp.Evaluate(js, &ready).Do(ctx); err == nil && ready {
				return nil
			}
			if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
				return err
			}
		}
		return errors.New("browser: consulta form (numeroProcesso) did not load")
	})
}

// fireSearch types the sample process number and clicks the "Buscar" button to
// trigger the authenticated API call.
func (b *Browser) fireSearch() chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		js := `(function(num){
			var inp = document.querySelector("input[formcontrolname='numeroProcesso']");
			if(!inp){ return false; }
			inp.value = num;
			inp.dispatchEvent(new Event('input', {bubbles:true}));
			inp.dispatchEvent(new Event('change', {bubbles:true}));
			var btn = Array.prototype.find.call(
				document.querySelectorAll('button'),
				function(b){ return (b.textContent||'').indexOf('Buscar') !== -1; });
			if(!btn){ return false; }
			btn.click();
			return true;
		})(` + jsString(sampleProcesso) + `)`
		var ok bool
		if err := chromedp.Evaluate(js, &ok).Do(ctx); err != nil {
			return fmt.Errorf("browser: fire search: %w", err)
		}
		if !ok {
			return errors.New("browser: could not type process number or click Buscar")
		}
		return nil
	})
}

// sleepCtx sleeps for d, returning early with ctx.Err() if the context is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
