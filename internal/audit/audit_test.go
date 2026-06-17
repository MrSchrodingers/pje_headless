package audit_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MrSchrodingers/pje_headless/internal/audit"
)

func TestIdentitySwitchLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	log := audit.New(&buf)
	audit.IdentitySwitch(log, "Marcos", "Bruna")
	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, "Marcos") || !strings.Contains(out, "Bruna") {
		t.Fatalf("esperado WARN com from/to; got %s", out)
	}
}

func TestNewReturnsJSONLogger(t *testing.T) {
	var buf bytes.Buffer
	log := audit.New(&buf)
	log.Info("probe")
	out := buf.String()
	if !strings.Contains(out, `"level":"INFO"`) || !strings.Contains(out, `"msg":"probe"`) {
		t.Fatalf("esperado JSON com level e msg; got %s", out)
	}
}
