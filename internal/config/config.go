package config

import (
	"os"
	"strings"
)

type Config struct {
	Mode          string   // "full" | "signer-only" (Plano 2 usa)
	SignerOrder   []string // ex.: ["pkcs11","pfx","remote"]
	PKCS11Module  string
	PKCS11Pin     string
	PKCS11Slot    string
	PKCS11Label   string
	PFXPath       string
	PFXPass       string
	PJeOfficePort string // default "8800"
	BindAddr      string // interface to bind; default "127.0.0.1" (loopback only)
	ChainDir      string // certs intermediarios/raiz (opcional)

	// Remote signer (Plano 2 — topologia LOCAL/REMOTO).
	// SignerRemoteAddr is the host:port of the remote SignerService gRPC endpoint.
	// Used when "remote" appears in SignerOrder.
	// SECURITY: plain TCP by default; only use on a trusted LAN/loopback.
	SignerRemoteAddr string // env PJE_SIGNER_REMOTE_ADDR, e.g. "127.0.0.1:9090"

	// GRPCAddr is the bind address for the SignerService gRPC server.
	// Used when Mode == "signer-only".
	// SECURITY: bind only to loopback or a trusted LAN interface.
	GRPCAddr string // env PJE_GRPC_ADDR, default ":9090"
}

func FromEnv() Config {
	return Config{
		Mode:             envOr("PJE_MODE", "full"),
		SignerOrder:      splitCSV(envOr("PJE_SIGNER_PRIORITY", "pkcs11,pfx")),
		PKCS11Module:     envOr("PJE_PKCS11_MODULE", "/usr/lib/libaetpkss.so"),
		PKCS11Pin:        os.Getenv("PJE_PKCS11_PIN"),
		PKCS11Slot:       os.Getenv("PJE_PKCS11_SLOT"),
		PKCS11Label:      os.Getenv("PJE_PKCS11_TOKEN_LABEL"),
		PFXPath:          os.Getenv("PJE_PFX_PATH"),
		PFXPass:          os.Getenv("PJE_PFX_PASS"),
		PJeOfficePort:    envOr("PJE_PJEOFFICE_PORT", "8800"),
		BindAddr:         envOr("PJE_BIND_ADDR", "127.0.0.1"),
		ChainDir:         os.Getenv("PJE_CHAIN_DIR"),
		SignerRemoteAddr: os.Getenv("PJE_SIGNER_REMOTE_ADDR"),
		GRPCAddr:         envOr("PJE_GRPC_ADDR", ":9090"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}
