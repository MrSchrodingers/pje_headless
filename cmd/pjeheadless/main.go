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
	"github.com/MrSchrodingers/pje_headless/internal/grpcsigner"
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
	default:
		runFull(cfg, log)
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
