package config

import (
	"testing"
)

// TestFromEnv_Defaults verifies that FromEnv returns the correct built-in
// defaults when no environment variables are set.
func TestFromEnv_Defaults(t *testing.T) {
	// Unset all env vars that FromEnv reads to ensure a clean baseline.
	envVars := []string{
		"PJE_MODE",
		"PJE_SIGNER_PRIORITY",
		"PJE_PKCS11_MODULE",
		"PJE_PKCS11_PIN",
		"PJE_PKCS11_SLOT",
		"PJE_PKCS11_TOKEN_LABEL",
		"PJE_PFX_PATH",
		"PJE_PFX_PASS",
		"PJE_PJEOFFICE_PORT",
		"PJE_BIND_ADDR",
		"PJE_CHAIN_DIR",
		"PJE_SIGNER_REMOTE_ADDR",
		"PJE_GRPC_ADDR",
		"PJE_LOGIN_GRPC_ADDR",
	}
	for _, k := range envVars {
		t.Setenv(k, "")
	}

	cfg := FromEnv()

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"Mode", cfg.Mode, "full"},
		{"PJeOfficePort", cfg.PJeOfficePort, "8800"},
		{"BindAddr", cfg.BindAddr, "127.0.0.1"},
		{"GRPCAddr", cfg.GRPCAddr, ":9090"},
		{"LoginGRPCAddr", cfg.LoginGRPCAddr, "127.0.0.1:9091"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestFromEnv_LoginGRPCAddrOverride verifies that PJE_LOGIN_GRPC_ADDR overrides
// the default ":9091".
func TestFromEnv_LoginGRPCAddrOverride(t *testing.T) {
	t.Setenv("PJE_LOGIN_GRPC_ADDR", ":19091")

	cfg := FromEnv()
	if cfg.LoginGRPCAddr != ":19091" {
		t.Errorf("LoginGRPCAddr: got %q, want %q", cfg.LoginGRPCAddr, ":19091")
	}
}
