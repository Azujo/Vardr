// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Plik z rejestracji (szablon) wczytuje się po wydzieleniu części wspólnej;
// nieznany klucz jest błędem.
func TestLoadConfigTemplate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "collector.yaml")
	body := configTemplate("https://192.168.88.98:8443") + "  # koniec\n"
	body = strings.Replace(body, "  # allow: [\"192.168.88.0/24\"]", "  allow: [\"192.168.88.0/24\"]", 1)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.URL != "https://192.168.88.98:8443" || c.Server.CertFile != filepath.Join(dir, "certs", "agent.crt") ||
		c.Syslog.UDP != ":514" || len(c.Syslog.Allow) != 1 || c.Buffer.OnFull != "drop_oldest" || c.Batch.MaxEvents != 2000 {
		t.Fatalf("konfiguracja: %+v", c)
	}
	if err := os.WriteFile(p, []byte(body+"nieznane: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Fatal("nieznany klucz powinien być błędem")
	}
}
