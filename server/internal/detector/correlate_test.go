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
	auth := authDDL(t, "corr_test")
	for _, q := range append([]string{"DROP DATABASE IF EXISTS corr_test", "CREATE DATABASE corr_test",
		strings.Replace(compatDDL, "compat_test.events", "corr_test.events", 1)}, auth...) {
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
	// Kubełki minutowe (etap 8) – brzegi okna liczone dokładnie:
	// piotr: 4 próby przed udanym i piąta w tej samej minucie, ale po nim → bez alertu;
	// kasia: 4 próby w oknie i piąta 20 s przed początkiem okna (ta sama minuta) → bez alertu.
	pb := now.Truncate(time.Minute).Add(-25 * time.Minute)
	at := func(t time.Time) time.Duration { return t.Sub(now) }
	for i := range 4 {
		evs = append(evs, ev("windows.security", 4625, "logon-failed", "failure", "piotr", "10.0.0.8", at(pb.Add(-time.Duration(i+1)*time.Minute)), nil))
	}
	evs = append(evs, ev("windows.security", 4625, "logon-failed", "failure", "piotr", "10.0.0.8", at(pb.Add(40*time.Second)), nil))
	evs = append(evs, ev("windows.security", 4624, "logon", "success", "piotr", "10.0.0.8", at(pb.Add(30*time.Second)), nil))
	kb := now.Truncate(time.Minute).Add(-8 * time.Minute)
	for i := range 4 {
		evs = append(evs, ev("windows.security", 4625, "logon-failed", "failure", "kasia", "10.0.0.9", at(kb.Add(-time.Duration(i+10)*time.Minute)), nil))
	}
	evs = append(evs, ev("windows.security", 4625, "logon-failed", "failure", "kasia", "10.0.0.9", at(kb.Add(-failureWindow+10*time.Second)), nil))
	evs = append(evs, ev("windows.security", 4624, "logon", "success", "kasia", "10.0.0.9", at(kb.Add(30*time.Second)), nil))
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

	c := &Correlator{Conn: conn, Table: "corr_test.auth_events"}
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

// authDDL: tabela logowań i widok zmaterializowany z deploy/lab/clickhouse/init/03-auth-events.sh
// (ten sam SQL co na serwerze) w bazie db. Sprawdza też, że warunki logowań
// w skrypcie są takie same jak authFailureSQL i authSuccessSQL.
func authDDL(t *testing.T, db string) []string {
	t.Helper()
	b, err := os.ReadFile("../../../deploy/lab/clickhouse/init/03-auth-events.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	cut := func(from, to string) string {
		i := strings.Index(src, from)
		j := strings.Index(src[max(i, 0):], to)
		if i < 0 || j < 0 {
			t.Fatalf("03-auth-events.sh: brak %q … %q", from, to)
		}
		return src[i : i+j]
	}
	sel := strings.TrimPrefix(cut(`select="`, "\"\n"), `select="`)
	for _, c := range []string{authFailureSQL, authSuccessSQL} {
		if !strings.Contains(oneLine(sel), oneLine(c)) {
			t.Fatalf("warunek logowań w 03-auth-events.sh różni się od correlate.go:\n%s", oneLine(c))
		}
	}
	table := cut("CREATE TABLE siem.auth_events", "SETTINGS")
	r := strings.NewReplacer("siem.", db+".", "$ttl", "3650")
	return []string{r.Replace(table), r.Replace("CREATE MATERIALIZED VIEW siem.auth_events_mv TO siem.auth_events AS " + sel)}
}
