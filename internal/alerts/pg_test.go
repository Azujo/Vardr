package alerts

import (
	"context"
	"os"
	"testing"
	"time"
)

// Test na prawdziwym PostgreSQL (SIEM_TEST_PG_URL, pusta baza testowa).
func TestPostgresAlerts(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.pool.Exec(ctx, "DROP SCHEMA IF EXISTS gjallarhorn CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if again, err := db.Migrate(ctx); err != nil || len(again) != 0 {
		t.Fatalf("ponowne migracje: %v %v", again, err)
	}
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	single := func(ev string, at time.Time) Hit {
		return Hit{RuleID: "r-log", RuleTitle: "Wyczyszczenie dziennika", Level: "high", Engine: "stream",
			GroupKey: ev, EventID: ev, EventTime: at, HostName: "dc01"}
	}
	grouped := func(ev string, at time.Time) Hit {
		return Hit{RuleID: "r-ps", RuleTitle: "PowerShell", Level: "medium", Engine: "stream",
			GroupFields: map[string]string{"Computer": "pc1"}, GroupKey: "pc1", Suppress: time.Hour, EventID: ev, EventTime: at}
	}

	res, err := db.Record(ctx, []Hit{single("e1", t0), grouped("p1", t0), grouped("p2", t0.Add(10*time.Minute))})
	if err != nil || res.NewAlerts != 2 || res.Merged != 1 {
		t.Fatalf("pierwszy zapis: %+v %v", res, err)
	}
	// Ponowne dostarczenie tych samych zdarzeń – bez zmian.
	res, err = db.Record(ctx, []Hit{single("e1", t0), grouped("p1", t0)})
	if err != nil || res.Duplicates != 2 || res.NewAlerts != 0 {
		t.Fatalf("ponowne dostarczenie: %+v %v", res, err)
	}
	// Trafienie poza oknem łączenia – nowy alert.
	res, _ = db.Record(ctx, []Hit{grouped("p3", t0.Add(3*time.Hour))})
	if res.NewAlerts != 1 {
		t.Fatalf("poza oknem: %+v", res)
	}
	list, err := db.Alerts(ctx, Filter{Status: "open"})
	if err != nil || len(list) != 3 {
		t.Fatalf("lista: %d %v", len(list), err)
	}
	var ps Alert
	for _, a := range list {
		if a.RuleID == "r-ps" && a.Hits == 2 {
			ps = a
		}
	}
	if ps.ID == 0 || !ps.LastSeen.Equal(t0.Add(10*time.Minute)) || ps.GroupFields["Computer"] != "pc1" {
		t.Fatalf("połączony alert: %+v", ps)
	}
	if evs, _ := db.AlertEvents(ctx, ps.ID, 10); len(evs) != 2 {
		t.Fatalf("zdarzenia alertu: %+v", evs)
	}
	// Outbox: po jednym wpisie na nowy alert; rezerwacja nie wydaje ich drugi raz.
	now := t0.Add(4 * time.Hour)
	p, err := db.ClaimOutbox(ctx, now, 10)
	if err != nil || len(p) != 3 {
		t.Fatalf("outbox: %d %v", len(p), err)
	}
	if again, _ := db.ClaimOutbox(ctx, now, 10); len(again) != 0 {
		t.Fatalf("zarezerwowane wpisy wydane ponownie: %d", len(again))
	}
	_ = db.MarkSent(ctx, p[0].OutboxID, now)
	_ = db.MarkFailed(ctx, p[1].OutboxID, "HTTP 500", now.Add(time.Minute))
	if retry, _ := db.ClaimOutbox(ctx, now.Add(3*time.Minute), 10); len(retry) != 2 {
		t.Fatalf("ponowienie po terminie: %d", len(retry))
	}
	// Zamknięcie alertu: kolejne trafienie z tym kluczem tworzy nowy alert.
	if _, err := db.SetStatus(ctx, ps.ID, "closed", "adam", "test", now); err != nil {
		t.Fatal(err)
	}
	res, _ = db.Record(ctx, []Hit{grouped("p4", t0.Add(15*time.Minute))})
	if res.NewAlerts != 1 {
		t.Fatalf("po zamknięciu: %+v", res)
	}
	// Reguły i podsumowanie.
	if err := db.SyncRules(ctx, []RuleInfo{{ID: "r-ps", Title: "PowerShell", Level: "medium", File: "a.yml", Source: "x", Mode: "both", Enabled: true}},
		[]RuleError{{File: "zla.yml", Error: "brak title"}}, now); err != nil {
		t.Fatal(err)
	}
	if s, err := db.Summarize(ctx, now); err != nil || s.Open != 3 || s.Rules != 1 || s.RuleErrs != 1 {
		t.Fatalf("podsumowanie: %+v %v", s, err)
	}
}
