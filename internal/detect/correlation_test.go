// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const baseCreated = `title: Utworzono konto
id: base-user-created
name: user_created
status: test
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4720}
  condition: sel
`

const baseAdded = `title: Dodano do grupy uprzywilejowanej
id: base-group-added
name: group_added
status: test
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: [4728, 4732, 4756]}
  condition: sel
`

const corrOrdered = `title: Nowe konto od razu w grupie administratorów
id: corr-new-admin
status: test
level: high
correlation:
  type: temporal_ordered
  rules: [user_created, group_added]
  group-by: [account]
  timespan: 1h
  aliases:
    account:
      user_created: TargetSid
      group_added: MemberSid
vardr:
  instructions: Sprawdź, kto utworzył konto {{SubjectUserName}}.
`

// withCond: typ i warunek korelacji (pod correlation, nie vardr).
func withCond(typ, cond string) string {
	s := strings.Replace(corrOrdered, "type: temporal_ordered", "type: "+typ, 1)
	if cond != "" {
		s = strings.Replace(s, "  timespan: 1h\n", "  timespan: 1h\n  condition: "+cond+"\n", 1)
	}
	return s
}

func TestParseCorrelation(t *testing.T) {
	c, err := ParseCorrelation([]byte(corrOrdered), "x.yml")
	if err != nil || c.Type != "temporal_ordered" || c.Timespan != time.Hour || c.Generate || c.Vardr.Suppress != Duration(time.Hour) {
		t.Fatalf("%+v %v", c, err)
	}
	for name, src := range map[string]string{
		"lt":              withCond("event_count", "{lt: 5}"),
		"brak warunku":    withCond("event_count", ""),
		"value bez pola":  withCond("value_count", "{gte: 3}"),
		"liczba 1":        withCond("event_count", "{gte: 1}"),
		"warunek czasowy": withCond("temporal", "{gte: 3}"),
		"jedna reguła":    strings.Replace(corrOrdered, "rules: [user_created, group_added]", "rules: [user_created]", 1),
		"okno 2d":         strings.Replace(corrOrdered, "timespan: 1h", "timespan: 2d", 1),
		"zły czas":        strings.Replace(corrOrdered, "timespan: 1h", "timespan: 1 hour", 1),
		"alias spoza":     strings.Replace(corrOrdered, "group_added: MemberSid", "inna: MemberSid", 1),
		"nieznany typ":    strings.Replace(corrOrdered, "temporal_ordered", "value_sum", 1),
		"próg w vardr":    corrOrdered + "  threshold: {count: 5, window: 5m}\n",
	} {
		if _, err := ParseCorrelation([]byte(src), "x.yml"); err == nil {
			t.Errorf("%s: brak błędu", name)
		}
	}
	c2, err := ParseCorrelation([]byte(withCond("event_count", "{gt: 9}")), "y.yml")
	if err != nil || c2.Count != 10 {
		t.Fatalf("gt 9 → 10: %+v %v", c2, err)
	}
	c3, err := ParseCorrelation([]byte(withCond("value_count", "{gte: 5, field: IpAddress}")), "z.yml")
	if err != nil || c3.Count != 5 || c3.Field != "IpAddress" {
		t.Fatalf("value_count: %+v %v", c3, err)
	}
}

func TestLoadSetCorrelation(t *testing.T) {
	dir := t.TempDir()
	// Korelacja z regułami bazowymi w jednym pliku.
	if err := os.WriteFile(filepath.Join(dir, "corr.yml"), []byte(baseCreated+"---\n"+baseAdded+"---\n# komentarz\n"+corrOrdered), 0o600); err != nil {
		t.Fatal(err)
	}
	set, errs, err := LoadSet(dir)
	if err != nil || len(errs) != 0 || len(set.Rules) != 2 || len(set.Correlations) != 1 {
		t.Fatalf("%+v %v %v", set, errs, err)
	}
	c := set.Correlations[0]
	if len(c.Rules) != 2 || c.Rules[0].ID != "base-user-created" || c.KeyField("account", 0) != "TargetSid" || c.KeyField("account", 1) != "MemberSid" {
		t.Fatalf("powiązanie: %+v", c.Rules)
	}
	for _, r := range set.Rules {
		if !r.CorrelationOnly || r.Alerts() {
			t.Fatalf("reguła bazowa z generate: false tworzy alerty: %s", r.ID)
		}
	}
	// generate: true – reguły bazowe zostają zwykłymi regułami.
	if err := os.WriteFile(filepath.Join(dir, "corr.yml"), []byte(baseCreated+"---\n"+baseAdded+"---\n"+
		strings.Replace(corrOrdered, "  timespan: 1h\n", "  timespan: 1h\n  generate: true\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	set, _, _ = LoadSet(dir)
	if set.Rules[0].CorrelationOnly {
		t.Fatal("generate: true – reguła bazowa powinna tworzyć alerty")
	}
	// Brak reguły bazowej – błąd, korelacja pominięta.
	if err := os.WriteFile(filepath.Join(dir, "corr.yml"), []byte(baseCreated+"---\n"+corrOrdered), 0o600); err != nil {
		t.Fatal(err)
	}
	set, errs, _ = LoadSet(dir)
	if len(set.Correlations) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Err, "group_added") {
		t.Fatalf("brak reguły bazowej: %+v %v", set.Correlations, errs)
	}
}

func TestEvaluateCorrelation(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	ev := func(min int, rule int, id string, isNew bool) CorrEvent {
		return CorrEvent{Time: t0.Add(time.Duration(min) * time.Minute), ID: id, Rules: []int{rule}, New: isNew, Value: id}
	}
	mk := func(typ string, n int, span time.Duration, rules int) *Correlation {
		c := &Correlation{Type: typ, Count: n, Timespan: span, Rules: make([]*Rule, rules)}
		c.Vardr.Suppress = Duration(max(time.Hour, span))
		if typ == "value_count" {
			c.Field = "x"
		}
		return c
	}
	// event_count: 3 w 10 min.
	c := mk("event_count", 3, 10*time.Minute, 1)
	if g := c.Evaluate([]CorrEvent{ev(0, 0, "a", true), ev(4, 0, "b", true), ev(9, 0, "c", true)}); len(g) != 1 || len(g[0]) != 3 {
		t.Fatalf("event_count: %v", g)
	}
	if g := c.Evaluate([]CorrEvent{ev(0, 0, "a", true), ev(6, 0, "b", true), ev(12, 0, "c", true)}); len(g) != 0 {
		t.Fatalf("event_count rozłożone szerzej niż okno: %v", g)
	}
	// Tylko stare zdarzenia – nic (było ocenione wcześniej).
	if g := c.Evaluate([]CorrEvent{ev(0, 0, "a", false), ev(4, 0, "b", false), ev(9, 0, "c", false)}); len(g) != 0 {
		t.Fatalf("bez nowych: %v", g)
	}
	// value_count: 3 różne wartości.
	v := mk("value_count", 3, 10*time.Minute, 1)
	same := []CorrEvent{ev(0, 0, "a", true), ev(1, 0, "a", true), ev(2, 0, "b", true)}
	same[1].Value, same[1].ID = "a", "a2"
	if g := v.Evaluate(same); len(g) != 0 {
		t.Fatalf("value_count – 2 różne: %v", g)
	}
	if g := v.Evaluate([]CorrEvent{ev(0, 0, "a", true), ev(1, 0, "b", true), ev(2, 0, "c", true)}); len(g) != 1 {
		t.Fatalf("value_count – 3 różne: %v", g)
	}
	// temporal: obie reguły w oknie, kolejność dowolna.
	tm := mk("temporal", 0, 30*time.Minute, 2)
	if g := tm.Evaluate([]CorrEvent{ev(0, 1, "b", true), ev(20, 0, "a", true)}); len(g) != 1 || len(g[0]) != 2 {
		t.Fatalf("temporal: %v", g)
	}
	if g := tm.Evaluate([]CorrEvent{ev(0, 1, "b", true), ev(40, 0, "a", true)}); len(g) != 0 {
		t.Fatalf("temporal poza oknem: %v", g)
	}
	// temporal_ordered: tylko w kolejności.
	o := mk("temporal_ordered", 0, time.Hour, 2)
	if g := o.Evaluate([]CorrEvent{ev(0, 1, "added", true), ev(10, 0, "created", true)}); len(g) != 0 {
		t.Fatalf("ordered – zła kolejność: %v", g)
	}
	g := o.Evaluate([]CorrEvent{ev(0, 0, "created", true), ev(5, 0, "other", true), ev(30, 1, "added", true), ev(200, 1, "late", true)})
	if len(g) != 1 || len(g[0]) != 2 || g[0][0].ID != "other" || g[0][1].ID != "added" {
		t.Fatalf("ordered – łańcuch z najpóźniejszym początkiem: %v", g)
	}
	if g := o.Evaluate([]CorrEvent{ev(0, 0, "created", true), ev(70, 1, "added", true)}); len(g) != 0 {
		t.Fatalf("ordered poza oknem: %v", g)
	}
}

// Reguły z panelu (LoadSetWith): korelacja odwołuje się do reguły z pliku,
// a powtórzone id przegrywa z plikiem.
func TestLoadSetWithPanel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "created.yml"), []byte(baseCreated), 0o600); err != nil {
		t.Fatal(err)
	}
	panel := []Source{{File: "panel/corr-new-admin.yml", Data: []byte(baseAdded + "---\n" + corrOrdered)},
		{File: "panel/dup.yml", Data: []byte(baseCreated)}}
	set, errs, err := LoadSetWith(dir, panel)
	if err != nil || len(set.Correlations) != 1 || len(set.Rules) != 2 {
		t.Fatalf("%+v %v %v", set, errs, err)
	}
	if len(errs) != 1 || errs[0].File != "panel/dup.yml" || !strings.Contains(errs[0].Err, "created.yml") {
		t.Fatalf("duplikat id: %v", errs)
	}
	if c := set.Correlations[0]; c.File != "panel/corr-new-admin.yml" || c.Rules[0].File != "created.yml" {
		t.Fatalf("powiązanie z plikiem: %s %s", c.File, c.Rules[0].File)
	}
}
