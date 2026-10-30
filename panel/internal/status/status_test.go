// SPDX-License-Identifier: AGPL-3.0-or-later

package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Prometheus na niby: odpowiedzi według fragmentu zapytania.
func TestReport(t *testing.T) {
	answers := map[string]string{
		`vector(1)`:                      `[{"metric":{},"value":[0,"1"]}]`,
		`up{service="ingest"}`:           `[{"metric":{},"value":[0,"1"]}]`,
		`up{service="detector"}`:         `[{"metric":{},"value":[0,"0"]}]`,
		`topk(1, siem_queue_fill_ratio)`: `[{"metric":{"consumer":"archiver"},"value":[0,"0.62"]}]`,
		`siem_archive_verify_ok`:         `[{"metric":{},"value":[0,"1"]}]`,
		`siem_detector_index_lag`:        `[]`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		res := `[]`
		for k, v := range answers {
			if strings.Contains(q, k) {
				res = v
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": json.RawMessage(res)}})
	}))
	defer srv.Close()
	rep := (&Prometheus{URL: srv.URL}).Report(context.Background(), time.Now())
	byName := map[string]Check{}
	for _, c := range rep.Checks {
		byName[c.Name] = c
	}
	if rep.Overall != Crit {
		t.Fatalf("stan ogólny: %s", rep.Overall)
	}
	if c := byName["Detekcja (siem-detector)"]; c.Status != Crit || c.Hint == "" {
		t.Fatalf("detektor: %+v", c)
	}
	if c := byName["Przyjmowanie zdarzeń (siem-ingest)"]; c.Status != OK || c.Hint != "" {
		t.Fatalf("ingest: %+v", c)
	}
	if c := byName["Najbardziej zapełniona kolejka"]; c.Status != Warn || c.Value != "62% (archiver)" || c.ValueKey != "queue" ||
		c.Args["n"] != 62.0 || c.Args["consumer"] != "archiver" || c.ID != "pipeline.queue" || c.GroupID != "pipeline" {
		t.Fatalf("kolejka: %+v", c)
	}
	if c := byName["Silnik zapytań – zaległość"]; c.Status != Disabled {
		t.Fatalf("silnik zapytań bez metryki: %+v", c)
	}
	if rep.Checks[0].Group != "Usługi" {
		t.Fatalf("kolejność grup: %s", rep.Checks[0].Group)
	}
	// Prometheus niedostępny.
	srv.Close()
	if rep := (&Prometheus{URL: srv.URL}).Report(context.Background(), time.Now()); rep.Overall != Crit || len(rep.Checks) != 1 {
		t.Fatalf("bez Prometheusa: %+v", rep)
	}
}

// Raport z prawdziwego Prometheusa (SIEM_TEST_PROMETHEUS_URL, np. laboratorium).
func TestReportLive(t *testing.T) {
	u := os.Getenv("SIEM_TEST_PROMETHEUS_URL")
	if u == "" {
		t.Skip("brak SIEM_TEST_PROMETHEUS_URL")
	}
	rep := (&Prometheus{URL: u}).Report(context.Background(), time.Now())
	for _, c := range rep.Checks {
		t.Logf("%-8s %-15s %-45s %s %s", c.Status, c.Group, c.Name, c.Value, c.Hint)
	}
	t.Logf("stan ogólny: %s", rep.Overall)
}

// Archiwum przed pierwszą weryfikacją: zapytania dają -1 – „w toku”, nie alarm.
func TestArchiveVerifyPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := `[]`
		if strings.Contains(r.URL.Query().Get("query"), "siem_archive_last_verify_timestamp_seconds) == 0") {
			res = `[{"metric":{},"value":[0,"-1"]}]`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"result": json.RawMessage(res)}})
	}))
	defer srv.Close()
	rep := (&Prometheus{URL: srv.URL}).Report(context.Background(), time.Now())
	n := 0
	for _, c := range rep.Checks {
		if c.ID == "archive.integrity" || c.ID == "archive.last_verify" {
			n++
			if c.Status != OK || c.ValueKey != "verify_pending" {
				t.Fatalf("%s: %+v", c.ID, c)
			}
		}
	}
	if n != 2 {
		t.Fatalf("sprawdzeń archiwum: %d", n)
	}
}
