// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// skeleton zastępuje literały tekstowe ClickHouse znakiem S (lekser jak
// w ClickHouse: \ poprzedza znak, dwa apostrofy to apostrof). ok=false –
// literał bez końca.
func skeleton(sql string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(sql); i++ {
		if sql[i] != '\'' {
			b.WriteByte(sql[i])
			continue
		}
		closed := false
		for i++; i < len(sql); i++ {
			if sql[i] == '\\' {
				i++
				continue
			}
			if sql[i] == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
					continue
				}
				closed = true
				break
			}
		}
		if !closed {
			return "", false
		}
		b.WriteByte('S')
	}
	return b.String(), true
}

// ruleSQL kompiluje regułę z polem field i wartością val we wszystkich
// modyfikatorach tekstowych, wyrażeniu regularnym i słowach kluczowych.
func ruleSQL(field, val string) (string, bool) {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	f, v := q(field), q(val)
	y := head + "  service: security\ndetection:\n  sel:\n" +
		"    " + f + ": " + v + "\n" +
		"    " + q(field+"|contains") + ": [" + v + ", 'b']\n" +
		"    " + q(field+"|startswith") + ": " + v + "\n" +
		"    " + q(field+"|endswith") + ": [" + v + ", 'e']\n" +
		"    " + q(field+"|contains|all") + ": [" + v + ", 'c']\n" +
		"  re:\n    " + q("Image|re") + ": " + q(regexp.QuoteMeta(val)) + "\n" +
		"  kw:\n    - " + v + "\n" +
		"  condition: sel or re or kw\n"
	r, err := Parse([]byte(y), "fuzz.yml")
	if err != nil {
		return "", false
	}
	return r.SQL(), true
}

// Wartości i nazwy pól z reguły (pisanej w panelu) nie zmieniają struktury
// zapytania: po wycięciu literałów SQL jest taki sam jak dla zwykłego tekstu
// o tym samym układzie znaków wieloznacznych.
func FuzzRuleSQL(f *testing.F) {
	for _, s := range []string{"x", "' OR 1=1 --", `\' OR 1 --`, `a\`, `\\'`, "''", "a*b?c", `\*`, "?", "/* */",
		"\x00", "zażółć", "a\nb", "'); DROP TABLE siem.events; --", `\x27`, "\\\\\\'"} {
		f.Add("CommandLine", s)
		f.Add("Pole '"+s, s)
	}
	f.Fuzz(func(t *testing.T, field, val string) {
		if field == "" || strings.ContainsAny(field, "|\n\r") || !strings.HasPrefix(FieldSQL(field), "multiIf(") || aliases[field] != nil {
			return // pola specjalne (kolumny, aliasy) mają inną postać
		}
		got, ok := ruleSQL(field, val)
		if !ok {
			return
		}
		benign := strings.Map(func(r rune) rune {
			if r == '*' || r == '?' || r == '\\' {
				return r
			}
			return 'x'
		}, val)
		want, ok := ruleSQL("PoleTestowe", benign)
		if !ok {
			t.Fatalf("reguła wzorcowa się nie kompiluje: %q", benign)
		}
		gs, ok1 := skeleton(got)
		ws, ok2 := skeleton(want)
		if !ok1 || !ok2 {
			t.Fatalf("niezamknięty literał: %q", got)
		}
		if gs != ws {
			t.Fatalf("struktura SQL zależy od wartości\npole %q wartość %q\n%s\n%s", field, val, gs, ws)
		}
	})
}

func TestRuleSQLHarness(t *testing.T) {
	got, ok := ruleSQL("Pole 'x", "' OR 1=1 --")
	if !ok || !strings.HasPrefix(FieldSQL("Pole 'x"), "multiIf(") {
		t.Fatal("reguła testowa się nie kompiluje")
	}
	if s, ok := skeleton(got); !ok || strings.Contains(s, "OR 1=1") {
		t.Fatalf("wartość poza literałem: %s", s)
	}
}
