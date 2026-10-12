package detector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/model"
	"siem/server/internal/chwriter"
)

// Korelacje międzyźródłowe na prawdziwym ClickHouse (SIEM_TEST_CH_ADDR jak
// w teście zgodności silników).
func TestCorrelations(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test korelacji na ClickHouse")
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
	for _, q := range []string{"DROP DATABASE IF EXISTS corr_test", "CREATE DATABASE corr_test",
		strings.Replace(compatDDL, "compat_test.events", "corr_test.events", 1)} {
		if err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	n := 0
	ev := func(ds string, code uint32, action, outcome, identity, ip string, at time.Duration, f map[string]string) model.Event {
		n++
		return model.Event{ID: fmt.Sprintf("e%d", n), AgentID: "a", Dataset: ds, Code: code, Action: action, Outcome: outcome,
			Identity: identity, UserName: identity, HostName: "h", SourceIP: ip, Timestamp: now.Add(at), Ingested: now.Add(at + time.Second),
			Fields: f, Parser: "test"}
	}
	geo := func(c string) map[string]string { return map[string]string{"source.geo.country_iso_code": c} }
	var evs []model.Event
	// jan: 3 próby w AD i 3 na VPN, potem udane logowanie w Entra → alert.
	for i := range 3 {
		evs = append(evs, ev("windows.security", 4625, "logon-failed", "failure", "jan", "10.0.0.5", time.Duration(-20+i)*time.Minute, nil))
		evs = append(evs, ev("fortinet.fortigate", 101039426, "ssl-login-fail", "failure", "jan", "203.0.113.9", time.Duration(-15+i)*time.Minute, nil))
	}
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "jan", "203.0.113.9", -5*time.Minute, geo("NL")))
	// ewa: 4 próby i udane – poniżej progu.
	for i := range 4 {
		evs = append(evs, ev("mikrotik.routeros", 0, "login", "failure", "ewa", "192.168.88.10", time.Duration(-10+i)*time.Minute, nil))
	}
	evs = append(evs, ev("mikrotik.routeros", 0, "login", "success", "ewa", "192.168.88.10", -2*time.Minute, nil))
	// ola: udane, potem próby – nie ta kolejność.
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "ola", "10.0.0.7", -20*time.Minute, geo("PL")))
	for i := range 6 {
		evs = append(evs, ev("azure.signinlogs", 50126, "sign-in", "failure", "ola", "10.0.0.7", time.Duration(-15+i)*time.Minute, nil))
	}
	// Historia krajów: jan – PL 5 dni temu (NL teraz → nowy kraj), ewa – PL i teraz PL, nowy – bez historii.
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "jan", "192.168.88.5", -5*24*time.Hour, geo("PL")))
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "ewa", "192.168.88.6", -3*24*time.Hour, geo("PL")))
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "ewa", "192.168.88.6", -3*time.Minute, geo("PL")))
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "nowy", "102.89.32.10", -3*time.Minute, geo("NG")))
	// Historia sprzed 40 dni się nie liczy: zosia – DE 40 dni temu, teraz US (bez historii w oknie – pominięta).
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "zosia", "1.2.3.4", -40*24*time.Hour, geo("DE")))
	evs = append(evs, ev("azure.signinlogs", 0, "sign-in", "success", "zosia", "5.6.7.8", -time.Minute, geo("US")))
	w := &chwriter.Writer{Conn: conn, Table: "corr_test.events"}
	if err := w.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if err := w.InsertEvents(ctx, evs[:5]); err != nil { // duplikaty jak przy ponownym dostarczeniu
		t.Fatal(err)
	}

	c := &Correlator{Conn: conn, Table: "corr_test.events"}
	hits, err := c.Run(ctx, now.Add(-time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string][]string{}
	for _, h := range hits {
		byRule[h.RuleID] = append(byRule[h.RuleID], h.GroupKey+"/"+h.EventID)
	}
	saf := byRule[SuccessAfterFailuresID]
	if len(saf) != 7 || !strings.HasPrefix(saf[0], "jan/") { // udane + 6 prób
		t.Fatalf("udane po nieudanych: %v", saf)
	}
	for _, h := range hits {
		if h.RuleID == SuccessAfterFailuresID && h.EventID == saf[0][4:] &&
			(!strings.Contains(h.Summary, "6 nieudanych") || !strings.Contains(h.Summary, "fortinet.fortigate, windows.security")) {
			t.Fatalf("opis: %s", h.Summary)
		}
	}
	nc := byRule[NewCountryID]
	if len(nc) != 1 || !strings.HasPrefix(nc[0], "jan\x1fNL/") {
		t.Fatalf("nowy kraj: %q", nc)
	}
	// Okno bez nowych zdarzeń – nic.
	if hits, err := c.Run(ctx, now.Add(time.Minute), now.Add(2*time.Minute)); err != nil || len(hits) != 0 {
		t.Fatalf("puste okno: %d %v", len(hits), err)
	}
}
