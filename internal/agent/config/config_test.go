package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsAndRelativePaths(t *testing.T) {
	p := write(t, `
server:
  url: https://localhost:8443/v1/ingest
  ca_file: certs/ca.crt
  cert_file: certs/agent.crt
  key_file: certs/agent.key
state_dir: data
channels:
  - name: Security
    event_ids: [4624, 4625]
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p)
	if c.Server.CAFile != filepath.Join(dir, "certs", "ca.crt") || c.StateDir != filepath.Join(dir, "data") {
		t.Errorf("ścieżki nie zostały rozwiązane względem pliku: %+v", c)
	}
	if c.StartAt != StartAtNow || c.Batch.MaxEvents != 500 || c.Batch.FlushInterval != 2*time.Second {
		t.Errorf("wartości domyślne: %+v", c)
	}
}

func TestLoadRejectsUnknownFieldsAndInvalid(t *testing.T) {
	if _, err := Load(write(t, "serwer: {}\n")); err == nil {
		t.Error("nieznane pole powinno być odrzucone")
	}
	_, err := Load(write(t, `
server: {url: "https://x"}
start_at: yesterday
channels: [{name: System}, {name: System}]
`))
	if err == nil {
		t.Fatal("oczekiwano błędów walidacji")
	}
	for _, want := range []string{"mTLS", "start_at", "wielokrotnie"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("brak błędu zawierającego %q w: %v", want, err)
		}
	}
}
