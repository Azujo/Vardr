// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"siem/internal/risk"
)

// Scoring ryzyka na PostgreSQL: rozstrzygnięcie przy zamknięciu, wejścia
// scoringu z alertów, zapis wyników z zachowaniem „poziom od” i odczyt
// dla panelu.
func TestPostgresRisk(t *testing.T) {
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
	now := time.Now().UTC().Truncate(time.Second)
	if cfg, err := db.RiskConfig(ctx); err != nil || !cfg.Enabled || cfg.HalfLifeDays != 14 {
		t.Fatalf("ustawienia domyślne: %+v %v", cfg, err)
	}
	var hits []Hit
	for i, ev := range []string{"a", "b", "c"} {
		hits = append(hits, Hit{RuleID: "r-" + ev, RuleTitle: "Reguła " + ev, Level: "high", Engine: "stream", GroupKey: ev,
			EventID: ev, EventTime: now.Add(-time.Duration(i) * time.Hour), HostName: "PC1", UserName: `AZUJO\jan`, Identity: "jan@azujo.pl"})
	}
	if _, err := db.Record(ctx, hits, nil); err != nil {
		t.Fatal(err)
	}
	list, _, err := db.Alerts(ctx, Filter{RuleID: "r-a", Limit: 1})
	if err != nil || len(list) != 1 {
		t.Fatalf("alert: %v %v", list, err)
	}
	if a, err := db.SetStatus(ctx, list[0].ID, "closed", "adam", "skaner podatności", risk.FalsePositive, now); err != nil || a.Resolution != risk.FalsePositive {
		t.Fatalf("zamknięcie z rozstrzygnięciem: %+v %v", a, err)
	}
	inputs, err := db.RiskInputs(ctx, now.Add(-24*time.Hour))
	if err != nil || len(inputs) != 3 {
		t.Fatalf("wejścia: %+v %v", inputs, err)
	}
	cfg := risk.Default()
	cfg.Thresholds[risk.Medium] = 10
	if err := db.SetRiskConfig(ctx, cfg, "adam", now); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.RiskConfig(ctx); got.Thresholds[risk.Medium] != 10 {
		t.Fatalf("zapis ustawień: %+v", got)
	}
	scores := risk.Compute(inputs, cfg, now)
	prev, err := db.SaveRiskScores(ctx, scores, now)
	if err != nil || len(prev) != 0 {
		t.Fatalf("pierwszy zapis: %v %v", prev, err)
	}
	jan, err := db.RiskScoreOf(ctx, risk.User, "jan@azujo.pl")
	if err != nil || jan.Alerts != 2 || jan.Level != risk.Medium || len(jan.Top) != 2 || !jan.LevelSince.Equal(now) {
		t.Fatalf("wynik osoby: %+v %v", jan, err)
	}
	// Ten sam poziom w kolejnej rundzie – „poziom od” bez zmian.
	later := now.Add(5 * time.Minute)
	prev, err = db.SaveRiskScores(ctx, scores, later)
	if err != nil || prev["user\x00jan@azujo.pl"] != risk.Medium {
		t.Fatalf("poprzednie poziomy: %v %v", prev, err)
	}
	if jan, _ := db.RiskScoreOf(ctx, risk.User, "jan@azujo.pl"); !jan.LevelSince.Equal(now) || !jan.UpdatedAt.Equal(later) {
		t.Fatalf("poziom od: %+v", jan)
	}
	if hosts, err := db.RiskScores(ctx, risk.Host, risk.Medium, 10); err != nil || len(hosts) != 1 || hosts[0].Display != "PC1" {
		t.Fatalf("ranking komputerów: %+v %v", hosts, err)
	}
	if none, err := db.RiskScores(ctx, risk.User, risk.Critical, 10); err != nil || len(none) != 0 {
		t.Fatalf("filtr poziomu: %+v %v", none, err)
	}
	if counts, err := db.RiskLevelCounts(ctx); err != nil || counts[risk.User][risk.Medium] != 1 || counts[risk.Host][risk.Medium] != 1 {
		t.Fatalf("liczby: %v %v", counts, err)
	}
	// Scoring wyłączony – wyniki znikają.
	if _, err := db.SaveRiskScores(ctx, nil, later); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RiskScoreOf(ctx, risk.User, "jan@azujo.pl"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("po wyczyszczeniu: %v", err)
	}
}
