package audit

import (
	"io"
	"log/slog"
)

func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func IdentitySwitch(log *slog.Logger, from, to string) {
	log.Warn("identidade ativa alterada", "event", "identity_switch", "from", from, "to", to)
}
