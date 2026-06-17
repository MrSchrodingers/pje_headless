package browser

import "testing"

// TestConfigFromEnvReadsTOTPSecret verifies the 2FA secret is sourced from the
// environment (PJE_2FA_TOTP_SECRET), never hardcoded, and that the other knobs
// are read too.
func TestConfigFromEnvReadsTOTPSecret(t *testing.T) {
	t.Setenv("PJE_2FA_TOTP_SECRET", "JBSWY3DPEHPK3PXP")
	t.Setenv("PJE_PJEOFFICE_PORT", "9001")
	t.Setenv("PJE_BIND_ADDR", "127.0.0.1")
	t.Setenv("PJE_CHROME_PATH", "/usr/bin/google-chrome")

	cfg := ConfigFromEnv()

	if cfg.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TOTPSecret = %q, want from env", cfg.TOTPSecret)
	}
	if cfg.PJeOfficePort != "9001" {
		t.Fatalf("PJeOfficePort = %q, want 9001", cfg.PJeOfficePort)
	}
	if cfg.PJeOfficeBindAddr != "127.0.0.1" {
		t.Fatalf("PJeOfficeBindAddr = %q, want 127.0.0.1", cfg.PJeOfficeBindAddr)
	}
	if cfg.ChromePath != "/usr/bin/google-chrome" {
		t.Fatalf("ChromePath = %q, want /usr/bin/google-chrome", cfg.ChromePath)
	}
}

// TestConfigFromEnvAbsentSecret verifies that an absent 2FA secret yields an
// empty field (so the loud-failure path is reached only when the page demands
// 2FA), and that New then applies loopback/port defaults.
func TestConfigFromEnvAbsentSecret(t *testing.T) {
	t.Setenv("PJE_2FA_TOTP_SECRET", "")
	t.Setenv("PJE_PJEOFFICE_PORT", "")
	t.Setenv("PJE_BIND_ADDR", "")
	t.Setenv("PJE_CHROME_PATH", "")

	cfg := ConfigFromEnv()
	if cfg.TOTPSecret != "" {
		t.Fatalf("TOTPSecret = %q, want empty when env unset", cfg.TOTPSecret)
	}

	b := New(stubSigner{}, cfg, nil)
	if b.cfg.PJeOfficeBindAddr != "127.0.0.1" {
		t.Fatalf("default BindAddr = %q, want 127.0.0.1", b.cfg.PJeOfficeBindAddr)
	}
	if b.cfg.PJeOfficePort != "8800" {
		t.Fatalf("default Port = %q, want 8800", b.cfg.PJeOfficePort)
	}
	if b.cfg.LoginTimeout <= 0 {
		t.Fatalf("default LoginTimeout = %v, want > 0", b.cfg.LoginTimeout)
	}
}
