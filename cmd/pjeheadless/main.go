package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/MrSchrodingers/pje_headless/internal/audit"
	"github.com/MrSchrodingers/pje_headless/internal/browser"
	"github.com/MrSchrodingers/pje_headless/internal/config"
	"github.com/MrSchrodingers/pje_headless/internal/grpclogin"
	"github.com/MrSchrodingers/pje_headless/internal/grpcsigner"
	"github.com/MrSchrodingers/pje_headless/internal/loginsvc"
	"github.com/MrSchrodingers/pje_headless/internal/pjeoffice"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

func main() {
	cfg := config.FromEnv()
	log := audit.New(os.Stderr)

	switch cfg.Mode {
	case "signer-only":
		runSignerOnly(cfg, log)
	case "login":
		runLogin(cfg, log)
	case "login-service":
		runLoginService(cfg, log)
	case "totp":
		runTotp(cfg, log)
	default:
		runFull(cfg, log)
	}
}

// runTotp prints the current jus.br TOTP code and its remaining validity once
// per second to stdout. It exists so a MANUAL browser login can read the 2FA
// code from `docker logs` of a dedicated container, without re-running a full
// login. The headless login modes compute the code themselves and do not use
// this. The secret comes from PJE_2FA_TOTP_SECRET; only the 6-digit code is
// printed, never the secret.
func runTotp(_ config.Config, log *slog.Logger) {
	secret := os.Getenv("PJE_2FA_TOTP_SECRET")
	if secret == "" {
		log.Error("modo totp: PJE_2FA_TOTP_SECRET ausente")
		os.Exit(1)
	}
	if _, _, err := browser.TOTPNow(secret); err != nil {
		log.Error("modo totp: segredo TOTP invalido", "err", err)
		os.Exit(1)
	}
	fmt.Println("pje_headless totp: codigo a cada 1s (docker logs --tail 1)")
	last := ""
	for {
		code, remaining, err := browser.TOTPNow(secret)
		if err != nil {
			log.Error("modo totp: falha ao gerar codigo", "err", err)
			os.Exit(1)
		}
		marker := ""
		if code != last {
			marker = "  <- novo"
		}
		fmt.Printf("[pje-2fa] codigo=%s expira_em=%2ds%s\n", code, remaining, marker)
		last = code
		time.Sleep(time.Second)
	}
}

// runFull starts the PJeOffice HTTP server (:8800) backed by the configured
// Signer. This is the standard "full" mode used by the pjeheadless container.
func runFull(cfg config.Config, log *slog.Logger) {
	s := buildSigner(cfg, log)
	srv := pjeoffice.NewServer(s, cfg.PJeOfficePort, cfg.BindAddr)
	srv.SetLogger(log)

	if err := srv.Start(); err != nil {
		log.Error("servidor encerrado", "err", err)
		os.Exit(1)
	}
}

// runSignerOnly starts the SignerService gRPC server (default :9090) wrapping
// the locally-configured Signer. This mode is intended for the srvtoken host
// that holds the hardware token or PFX file.
//
// SECURITY: plain TCP by default. Bind only to loopback or a trusted LAN
// interface via PJE_GRPC_ADDR. mTLS is a backlog hardening item.
func runSignerOnly(cfg config.Config, log *slog.Logger) {
	s := buildSigner(cfg, log)

	// Login eager no token na inicializacao: assim o Health reporta "ready" e o
	// RemoteSigner do consumidor nao aborta com "server not ready". Fail-fast: um
	// PIN errado ou token ausente quebra aqui, na partida, e nao no meio do fluxo.
	if err := s.Login(context.Background()); err != nil {
		log.Error("signer-only: falha ao autenticar no token na inicializacao", "err", err)
		os.Exit(1)
	}
	log.Info("signer-only: token autenticado e pronto")

	srv := grpcsigner.NewSignerServiceServer(s, log)

	log.Info("modo signer-only: iniciando gRPC", "addr", cfg.GRPCAddr)
	if err := grpcsigner.ListenAndServe(cfg.GRPCAddr, srv, log); err != nil {
		log.Error("SignerService encerrado", "err", err)
		os.Exit(1)
	}
}

// buildSigner constructs the active Signer from the environment configuration.
// It mirrors the priority order expressed in cfg.SignerOrder:
//   - "pkcs11" -> PKCS11Signer (requires hardware token)
//   - "pfx"    -> PFXSigner    (file-based A1 certificate)
//   - "remote" -> RemoteSigner (delegates to a SignerService via gRPC)
//
// When SignerOrder contains more than one entry, a DualSigner is returned so
// that the highest-priority available backend is used transparently on each call.
// Unrecognised entries in SignerOrder are logged and skipped.
func buildSigner(cfg config.Config, log *slog.Logger) signer.Signer {
	signers := buildOrderedSigners(cfg, log)
	if len(signers) == 0 {
		log.Warn("nenhum backend de assinatura configurado; usando PFX por padrao")
		return signer.NewPFXSigner(cfg.PFXPath, cfg.PFXPass, cfg.ChainDir)
	}
	if len(signers) == 1 {
		return signers[0]
	}
	return signer.NewDual(signers, log)
}

// buildOrderedSigners returns the list of Signers in the priority order defined
// by cfg.SignerOrder. It is extracted as a separate function to keep buildSigner
// testable without the fallback logic.
func buildOrderedSigners(cfg config.Config, log *slog.Logger) []signer.Signer {
	var signers []signer.Signer
	for _, name := range cfg.SignerOrder {
		switch name {
		case "pkcs11":
			signers = append(signers, signer.NewPKCS11Signer(
				cfg.PKCS11Module,
				cfg.PKCS11Pin,
				cfg.PKCS11Slot,
				cfg.PKCS11Label,
				cfg.ChainDir,
			))
		case "pfx":
			signers = append(signers, signer.NewPFXSigner(cfg.PFXPath, cfg.PFXPass, cfg.ChainDir))
		case "remote":
			if cfg.SignerRemoteAddr == "" {
				log.Warn("entrada 'remote' em PJE_SIGNER_PRIORITY ignorada: PJE_SIGNER_REMOTE_ADDR nao configurado")
				continue
			}
			signers = append(signers, signer.NewRemoteSigner(cfg.SignerRemoteAddr))
		default:
			log.Warn("entrada desconhecida em PJE_SIGNER_PRIORITY ignorada", "entry", name)
		}
	}
	return signers
}

// runLoginService starts the LoginService gRPC server (default :9091).
// It builds the dual signer via buildSigner, wraps the headless browser login
// in a loginFn, creates a LoginManager for session reuse, and serves on
// cfg.LoginGRPCAddr.
//
// SECURITY: plain TCP by default. Bind only to loopback or a trusted LAN
// interface via PJE_LOGIN_GRPC_ADDR. The bearer is a credential; do not
// expose this port on an untrusted network without TLS.
func runLoginService(cfg config.Config, log *slog.Logger) {
	s := buildSigner(cfg, log)
	bcfg := browser.ConfigFromEnv()

	loginFn := func(ctx context.Context) (string, error) {
		// Bound the expensive headless login independently of the caller's ctx:
		// a gRPC client without a deadline must not be able to pin the browser
		// login (and, via the manager's coalescing, every waiter attached to it)
		// indefinitely. Mirrors runLogin's explicit timeout.
		timeout := bcfg.LoginTimeout
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return browser.New(s, bcfg, log).Login(lctx)
	}

	mgr := loginsvc.NewManager(loginFn, 0, log)
	srv := grpclogin.NewLoginServiceServer(mgr, log)

	log.Info("login-service: starting gRPC", "addr", cfg.LoginGRPCAddr)
	if err := grpclogin.ListenAndServe(cfg.LoginGRPCAddr, srv, log); err != nil {
		log.Error("LoginService stopped", "err", err)
		os.Exit(1)
	}
}

// runLogin executes a single headless jus.br login using the configured Signer
// (e.g. PJE_SIGNER_PRIORITY=remote -> RemoteSigner to the token host) and prints
// a masked confirmation of the captured bearer. End-to-end driver: proves the
// full dual flow (browser + :8800 + signer) against the live SSO. The full
// bearer is never logged.
func runLogin(cfg config.Config, log *slog.Logger) {
	s := buildSigner(cfg, log)
	b := browser.New(s, browser.ConfigFromEnv(), log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	bearer, err := b.Login(ctx)
	if err != nil {
		log.Error("login falhou", "err", err)
		os.Exit(1)
	}

	masked := bearer
	if len(masked) > 28 {
		masked = masked[:20] + "..." + masked[len(masked)-6:]
	}
	log.Info("LOGIN OK", "bearer_masked", masked, "bearer_len", len(bearer))
	fmt.Printf("LOGIN_OK bearer_len=%d\n", len(bearer))
}
