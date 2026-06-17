package main

import (
	"log/slog"
	"os"

	"github.com/MrSchrodingers/pje_headless/internal/audit"
	"github.com/MrSchrodingers/pje_headless/internal/config"
	"github.com/MrSchrodingers/pje_headless/internal/pjeoffice"
	"github.com/MrSchrodingers/pje_headless/internal/signer"
)

func main() {
	cfg := config.FromEnv()
	log := audit.New(os.Stderr)

	s := buildSigner(cfg, log)

	srv := pjeoffice.NewServer(s, cfg.PJeOfficePort)
	srv.SetLogger(log)

	if err := srv.Start(); err != nil {
		log.Error("servidor encerrado", "err", err)
		os.Exit(1)
	}
}

// buildSigner constructs the active Signer from the environment configuration.
// It mirrors the priority order expressed in cfg.SignerOrder:
//   - "pkcs11" -> PKCS11Signer (requires hardware token)
//   - "pfx"    -> PFXSigner    (file-based A1 certificate)
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
		default:
			log.Warn("entrada desconhecida em PJE_SIGNER_PRIORITY ignorada", "entry", name)
		}
	}
	return signers
}
