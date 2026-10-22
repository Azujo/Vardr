// SPDX-License-Identifier: AGPL-3.0-or-later

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
	if r := c.Limits.Resource(); r.Priority != "below_normal" || r.MemorySoftMB != 150 || r.MemoryHardMB != 400 || r.CPUMaxPercent != 0 {
		t.Errorf("domyślne limity: %+v", r)
	}
}

func TestLimitsExplicitZeroDisables(t *testing.T) {
	c, err := Load(write(t, `
server: {url: "https://x", ca_file: a, cert_file: b, key_file: c}
limits: {priority: background, cpu_max_percent: 5, memory_soft_mb: 0, memory_hard_mb: 0, max_eps: 200}
channels: [{name: System}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Limits.Resource(); r.MemorySoftMB != 0 || r.MemoryHardMB != 0 || r.CPUMaxPercent != 5 || c.Limits.MaxEPS != 200 {
		t.Errorf("limity: %+v / %+v", r, c.Limits)
	}

	if _, err := Load(write(t, `
server: {url: "https://x", ca_file: a, cert_file: b, key_file: c}
limits: {memory_soft_mb: 100, memory_hard_mb: 110}
channels: [{name: System}]
`)); err == nil || !strings.Contains(err.Error(), "bezpiecznik") {
		t.Errorf("twardy limit zbyt blisko miękkiego powinien być odrzucony: %v", err)
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
