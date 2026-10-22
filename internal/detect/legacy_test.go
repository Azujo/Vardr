// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strings"
	"testing"
	"time"
)

// Reguły sprzed zmiany nazwy na Vardr (klucz „heimdall”, także import
// SigmaHQ z dopisanym heimdall: enabled: false) wczytują się bez zmian.
func TestLegacyExtensionsKey(t *testing.T) {
	const base = `title: T
id: legacy-key-1
level: low
logsource: {product: windows, service: security}
detection: {sel: {EventID: 4625}, condition: sel}
`
	r := mustRule(t, base+"heimdall:\n  enabled: false\n  group_by: [user.name]\n")
	if r.Enabled() || len(r.Vardr.GroupBy) != 1 || time.Duration(r.Vardr.Suppress) != time.Hour {
		t.Fatalf("dawny klucz: %+v", r.Vardr)
	}
	if r := mustRule(t, base+"vardr:\n  enabled: false\n"); r.Enabled() {
		t.Fatal("klucz vardr")
	}
	if _, err := Parse([]byte(base+"vardr:\n  mode: stream\nheimdall:\n  enabled: false\n"), "x.yml"); err == nil ||
		!strings.Contains(err.Error(), "naraz") {
		t.Fatalf("oba klucze: %v", err)
	}
}
