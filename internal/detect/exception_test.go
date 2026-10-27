// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strings"
	"testing"
)

// Wyjątek: zdarzenia z warunku wyjątku nie trafiają w regułę (Eval i SQL),
// inne reguły bez zmian; błędny wyjątek pominięty, reguła działa dalej.
func TestApplyExceptions(t *testing.T) {
	r := mustRule(t, head+`  service: security
detection:
  sel:
    EventID: 4625
  condition: sel
`)
	other := mustRule(t, strings.Replace(head, "test-rule", "other-rule", 1)+`  service: security
detection:
  sel:
    EventID: 4625
  condition: sel
`)
	errs := ApplyExceptions([]*Rule{r, other}, []Exception{
		{ID: 1, RuleID: "test-rule", Match: map[string]any{"TargetUserName": "svc_backup", "IpAddress|cidr": "10.0.0.0/8"}},
		{ID: 2, RuleID: "test-rule", Match: map[string]any{"TargetUserName|startswith": "scan"}},
		{ID: 3, RuleID: "test-rule", Match: map[string]any{"Pole|zly": "x"}},
		{ID: 4, RuleID: "test-rule", Match: map[string]any{}},
	})
	if len(errs) != 2 || r.Exceptions != 2 || other.Exceptions != 0 {
		t.Fatalf("błędy %v, wyjątki %d/%d", errs, r.Exceptions, other.Exceptions)
	}
	cases := []struct {
		f    map[string]string
		want bool
	}{
		{map[string]string{"TargetUserName": "svc_backup", "IpAddress": "10.1.2.3"}, false},   // wyjątek 1
		{map[string]string{"TargetUserName": "SVC_BACKUP", "IpAddress": "192.168.1.5"}, true}, // inny adres
		{map[string]string{"TargetUserName": "scanner01"}, false},                             // wyjątek 2
		{map[string]string{"TargetUserName": "jan"}, true},
	}
	for i, c := range cases {
		e := ev("Security", 4625, c.f)
		if got := r.Match(e); got != c.want {
			t.Errorf("przypadek %d: %v, oczekiwano %v", i, got, c.want)
		}
		if !other.Match(e) {
			t.Errorf("przypadek %d: wyjątek zadziałał na inną regułę", i)
		}
	}
	if sql := r.SQL(); !strings.Contains(sql, "NOT") || strings.Contains(other.SQL(), "NOT") {
		t.Fatalf("SQL: %s", sql)
	}
	if _, err := ExceptionSQL(map[string]any{"TargetUserName": ""}); err == nil {
		t.Fatal("pusta wartość przyjęta")
	}
}

func TestSuppressed(t *testing.T) {
	r := mustRule(t, head+`  service: security
detection:
  sel:
    EventID: 4625
  condition: sel
`)
	s, err := Suppressed(r, map[string]any{"TargetUserName|startswith": "svc_"})
	if err != nil {
		t.Fatal(err)
	}
	hit := ev("Security", 4625, map[string]string{"TargetUserName": "svc_backup"})
	other := ev("Security", 4625, map[string]string{"TargetUserName": "jan"})
	if !s.Match(hit) || s.Match(other) {
		t.Fatal("Suppressed powinno trafiać tylko w zdarzenia ukrywane przez wyjątek")
	}
	if !r.Match(other) || !r.Match(hit) {
		t.Fatal("Suppressed nie może zmieniać oryginału")
	}
}
