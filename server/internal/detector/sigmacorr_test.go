// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/detect"
	"siem/internal/model"
	"siem/server/internal/chwriter"
)

// Reguły korelacyjne Sigma na prawdziwym ClickHouse: temporal_ordered
// z aliasami pól (SID nowego konta w 4720 i członka grupy w 4728) oraz
// value_count (różne adresy prób jednego konta).
func TestSigmaCorrelations(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test korelacji Sigma na ClickHouse")
	}
	ctx := context.Background()
	user := os.Getenv("SIEM_TEST_CH_USER")
	if user == "" {
		user = "default"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr},
		Auth: clickhouse.Auth{Username: user, Password: os.Getenv("SIEM_TEST_CH_PASSWORD")}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, q := range []string{"DROP DATABASE IF EXISTS sigma_test", "CREATE DATABASE sigma_test",
		strings.Replace(compatDDL, "compat_test.events", "sigma_test.events", 1)} {
		if err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	dir := t.TempDir()
	rules := `title: Utworzono konto
id: base-user-created
name: user_created
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4720}
  condition: sel
---
title: Dodano do grupy uprzywilejowanej
id: base-group-added
name: group_added
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: [4728, 4732, 4756]}
  condition: sel
---
title: Nowe konto od razu w grupie administratorów
id: corr-new-admin
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
  instructions: "Konto {{TargetUserName}}: {{count}} zdarzeń ({{rules}})."
---
title: Nieudane logowanie
id: base-logon-failed
name: logon_failed
level: low
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel
---
title: Konto atakowane z wielu adresów
id: corr-many-sources
level: medium
correlation:
  type: value_count
  rules: [logon_failed]
  group-by: [TargetUserName]
  timespan: 15m
  condition: {gte: 3, field: IpAddress}
`
	if err := os.WriteFile(filepath.Join(dir, "c.yml"), []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	set, errs, err := detect.LoadSet(dir)
	if err != nil || len(errs) != 0 || len(set.Correlations) != 2 {
		t.Fatalf("%v %v %+v", errs, err, set)
	}

	now := time.Now().UTC().Truncate(time.Second)
	n := 0
	ev := func(code uint32, at time.Duration, f map[string]string) model.Event {
		n++
		f["winlog.channel"] = "Security"
		return model.Event{ID: fmt.Sprintf("s%d", n), AgentID: "agt-dc", Dataset: "windows.security", Code: code, HostName: "dc01",
			Timestamp: now.Add(at), Ingested: now.Add(at + time.Second), Fields: f, Parser: "test"}
	}
	var evs []model.Event
	// Konto A: utworzone, po 20 min w grupie → alert.
	evs = append(evs, ev(4720, -40*time.Minute, map[string]string{"TargetSid": "S-1-5-21-1-1001", "TargetUserName": "nowy.admin", "SubjectUserName": "intruz"}))
	evs = append(evs, ev(4728, -20*time.Minute, map[string]string{"MemberSid": "S-1-5-21-1-1001", "TargetUserName": "Domain Admins"}))
	// Konto B: najpierw w grupie, potem „utworzone” (zła kolejność) → bez alertu.
	evs = append(evs, ev(4728, -30*time.Minute, map[string]string{"MemberSid": "S-1-5-21-1-1002", "TargetUserName": "Domain Admins"}))
	evs = append(evs, ev(4720, -10*time.Minute, map[string]string{"TargetSid": "S-1-5-21-1-1002", "TargetUserName": "inne"}))
	// Konto C: utworzone 2 h temu, w grupie teraz (poza oknem 1h) → bez alertu.
	evs = append(evs, ev(4720, -120*time.Minute, map[string]string{"TargetSid": "S-1-5-21-1-1003", "TargetUserName": "stare"}))
	evs = append(evs, ev(4728, -5*time.Minute, map[string]string{"MemberSid": "S-1-5-21-1-1003", "TargetUserName": "Domain Admins"}))
	// value_count: jan z 3 adresów w 10 min → alert; ewa z 1 adresu 5 razy → bez.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		evs = append(evs, ev(4625, time.Duration(-12+i*4)*time.Minute, map[string]string{"TargetUserName": "jan", "IpAddress": ip}))
	}
	for i := range 5 {
		evs = append(evs, ev(4625, time.Duration(-12+i)*time.Minute, map[string]string{"TargetUserName": "ewa", "IpAddress": "10.9.9.9"}))
	}
	w := &chwriter.Writer{Conn: conn, Table: "sigma_test.events"}
	if err := w.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if err := w.InsertEvents(ctx, evs[:2]); err != nil { // duplikaty
		t.Fatal(err)
	}

	c := &Correlator{Conn: conn, Events: "sigma_test.events"}
	hits, rerrs := c.RunSigma(ctx, set.Correlations, now.Add(-time.Hour), now.Add(time.Minute))
	if len(rerrs) != 0 {
		t.Fatal(rerrs)
	}
	byRule := map[string][]string{}
	for _, h := range hits {
		byRule[h.RuleID] = append(byRule[h.RuleID], h.GroupKey+"/"+h.EventID)
	}
	if got := byRule["corr-new-admin"]; len(got) != 2 || !strings.HasPrefix(got[0], "s-1-5-21-1-1001/") {
		t.Fatalf("nowe konto w grupie: %v", got)
	}
	for _, h := range hits {
		if h.RuleID == "corr-new-admin" && !strings.Contains(h.Instructions, "2 zdarzeń") {
			t.Fatalf("instrukcja: %q", h.Instructions)
		}
	}
	if got := byRule["corr-many-sources"]; len(got) != 3 || !strings.HasPrefix(got[0], "jan/") {
		t.Fatalf("wiele adresów: %v", got)
	}
	// Okno bez nowych zdarzeń – nic.
	if hits, errs := c.RunSigma(ctx, set.Correlations, now.Add(time.Minute), now.Add(2*time.Minute)); len(hits) != 0 || len(errs) != 0 {
		t.Fatalf("puste okno: %v %v", hits, errs)
	}
	// Wyłączona korelacja – pomijana.
	off := false
	set.Correlations[0].Vardr.Enabled = &off
	if hits, _ := c.RunSigma(ctx, set.Correlations[:1], now.Add(-time.Hour), now.Add(time.Minute)); len(hits) != 0 {
		t.Fatalf("wyłączona: %v", hits)
	}
}
