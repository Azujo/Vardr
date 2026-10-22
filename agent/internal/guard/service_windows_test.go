// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package guard

import (
	"strings"
	"testing"
)

func TestSDDL(t *testing.T) {
	p, o := canonical(ProtectedSDDL), canonical(OpenSDDL)
	if p == o || !strings.HasPrefix(p, "D:") || !strings.HasPrefix(o, "D:") {
		t.Fatalf("%q %q", p, o)
	}
	// Administratorzy (BA): bez zatrzymania (WP), usunięcia (SD) i zmiany konfiguracji (DC).
	for _, ace := range strings.Split(strings.TrimPrefix(p, "D:"), ")(") {
		if strings.HasSuffix(strings.TrimSuffix(ace, ")"), ";;;BA") {
			rights := strings.Split(ace, ";")[2]
			for _, bad := range []string{"WP", "SD", "DC", "DT", "WO"} {
				if strings.Contains(rights, bad) {
					t.Errorf("administratorzy mają %s: %s", bad, rights)
				}
			}
			if !strings.Contains(rights, "RP") || !strings.Contains(rights, "CR") {
				t.Errorf("administratorzy bez startu albo poleceń agenta: %s", rights)
			}
		}
	}
	if BootTime().IsZero() {
		t.Fatal("czas startu systemu")
	}
}
