// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"strings"
	"testing"
)

func TestSigmaHQAttribution(t *testing.T) {
	own := RuleInfo{File: "windows/security_log_cleared.yml", Source: "author: Vardr\n"}
	if own.SigmaHQAttribution() != nil {
		t.Fatal("reguła Vardra bez wskazania SigmaHQ")
	}
	r := RuleInfo{File: "sigmahq/windows/process_creation/proc_creation_win_x.yml",
		Source: "title: X\nauthor: Jan Kowalski, Anna Nowak\nlevel: high\n"}
	a := r.SigmaHQAttribution()
	if a == nil || a.Author != "Jan Kowalski, Anna Nowak" ||
		a.RuleURL != "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_x.yml" ||
		!strings.Contains(a.Line(), "DRL") {
		t.Fatalf("%+v", a)
	}
	if b := (RuleInfo{File: "sigmahq/x.yml", Source: "title: X\n"}).SigmaHQAttribution(); b == nil || !strings.Contains(b.Author, "nieznany") {
		t.Fatalf("bez autora: %+v", b)
	}
}
