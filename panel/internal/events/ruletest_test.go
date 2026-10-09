package events

import (
	"context"
	"os"
	"testing"
	"time"

	"siem/internal/detect"
)

// Test reguły na prawdziwym ClickHouse z danymi (np. laboratorium):
// SIEM_TEST_CH_ADDR/USER/PASSWORD, SIEM_TEST_RULE (plik reguły),
// SIEM_TEST_RULE_HOURS (domyślnie 24).
func TestRuleOnClickHouse(t *testing.T) {
	addr, file := os.Getenv("SIEM_TEST_CH_ADDR"), os.Getenv("SIEM_TEST_RULE")
	if addr == "" || file == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR albo SIEM_TEST_RULE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Open(ctx, addr, os.Getenv("SIEM_TEST_CH_USER"), os.Getenv("SIEM_TEST_CH_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	r, err := detect.Parse(data, file)
	if err != nil {
		t.Fatal(err)
	}
	hours := 24
	if v := os.Getenv("SIEM_TEST_RULE_HOURS"); v != "" {
		if d, err := time.ParseDuration(v + "h"); err == nil {
			hours = int(d.Hours())
		}
	}
	to := time.Now()
	res, err := s.TestRule(ctx, r, to.Add(-time.Duration(hours)*time.Hour), to)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: pasujące %d, alerty %d (%d ms)", r.Title, res.Matched, res.AlertsTotal, res.TookMS)
	for _, a := range res.Alerts {
		t.Logf("  alert: %v %d zdarzeń %s – %s", a.Key, a.Events, a.First.Format(time.RFC3339), a.Last.Format(time.RFC3339))
	}
	if res.Matched == 0 || res.AlertsTotal == 0 {
		t.Fatal("oczekiwano dopasowań i alertów w danych testowych")
	}
}
