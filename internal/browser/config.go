package browser

import "os"

// Env var names consumed by ConfigFromEnv. Kept local to the browser package so
// wiring the login does not require editing internal/config.
const (
	envTOTPSecret    = "PJE_2FA_TOTP_SECRET"
	envPJeOfficePort = "PJE_PJEOFFICE_PORT"
	envBindAddr      = "PJE_BIND_ADDR"
	envChromePath    = "PJE_CHROME_PATH"
)

// ConfigFromEnv builds a Config from environment variables. The 2FA secret is
// read from PJE_2FA_TOTP_SECRET; it is never hardcoded. Empty/absent values
// leave the corresponding field empty so New can apply its defaults (and so an
// absent 2FA secret triggers the "2FA exigido mas PJE_2FA_TOTP_SECRET ausente"
// failure only if the page actually demands a code).
func ConfigFromEnv() Config {
	return Config{
		PJeOfficeBindAddr: os.Getenv(envBindAddr),
		PJeOfficePort:     os.Getenv(envPJeOfficePort),
		TOTPSecret:        os.Getenv(envTOTPSecret),
		ChromePath:        os.Getenv(envChromePath),
	}
}
