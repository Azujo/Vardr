package attack

import (
	"strings"
	"testing"
)

func TestEnterprise(t *testing.T) {
	d := Enterprise()
	if d.Version == "" || len(d.Tactics) < 14 || len(d.Techniques) < 500 {
		t.Fatalf("słownik: %s, %d taktyk, %d technik", d.Version, len(d.Tactics), len(d.Techniques))
	}
	pg, ok := d.Technique("t1110.001")
	if !ok || pg.Name != "Password Guessing" || pg.Parent() != "T1110" || pg.URL() != "https://attack.mitre.org/techniques/T1110/001/" {
		t.Fatalf("T1110.001: %+v", pg)
	}
	if ca, ok := d.Tactic("credential-access"); !ok || ca.ID != "TA0006" {
		t.Fatalf("taktyka: %+v", ca)
	}
}

func TestMap(t *testing.T) {
	d := Enterprise()
	m := d.Map([]string{"attack.credential_access", "attack.t1110.001", "attack.T1098", "attack.g0016", "cve.2021-1234"})
	if len(m.Techniques) != 2 || len(m.Warnings) != 0 {
		t.Fatalf("mapowanie: %+v", m)
	}
	// T1098 dokłada swoje taktyki (persistence, privilege-escalation), kolejność macierzy.
	if strings.Join(m.Tactics, ",") != "persistence,privilege-escalation,credential-access" {
		t.Fatalf("taktyki: %v", m.Tactics)
	}
	if !Covers(m, "T1110") || !Covers(m, "t1110.001") || Covers(m, "T1110.003") {
		t.Fatal("pokrycie techniki nadrzędnej")
	}
	w := d.Map([]string{"attack.t9999", "attack.defense_evasion", "attack.cośtam"}).Warnings
	if len(w) != 3 || !strings.Contains(w[0], "nieznana technika") || !strings.Contains(w[1], "podzielona") {
		t.Fatalf("ostrzeżenia: %v", w)
	}
	// Technika wycofana – z następcą.
	for _, tt := range d.Techniques {
		if tt.Deprecated && tt.ReplacedBy != "" {
			w := d.Map([]string{"attack." + strings.ToLower(tt.ID)}).Warnings
			if len(w) != 1 || !strings.Contains(w[0], tt.ReplacedBy) {
				t.Fatalf("wycofana %s: %v", tt.ID, w)
			}
			break
		}
	}
}
