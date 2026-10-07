package api

import (
	"context"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"siem/panel/internal/api/store"
	"siem/panel/internal/events"
)

type fakeSearcher struct {
	gotFrom, gotTo time.Time
	gotBefore      *events.Cursor
	gotConds       int
}

func (f *fakeSearcher) Search(_ context.Context, p events.Parsed, from, to time.Time, before *events.Cursor, limit int) ([]events.Event, error) {
	f.gotFrom, f.gotTo, f.gotBefore, f.gotConds = from, to, before, len(p.Conds)
	out := make([]events.Event, limit)
	for i := range out {
		out[i] = events.Event{ID: "e" + itoa(int64(i)), Timestamp: to.Add(-time.Duration(i) * time.Second)}
	}
	return out, nil
}
func (f *fakeSearcher) Histogram(context.Context, events.Parsed, time.Time, time.Time) ([]events.Bucket, time.Duration, uint64, error) {
	return []events.Bucket{{Count: 3}}, time.Minute, 3, nil
}
func (f *fakeSearcher) Get(_ context.Context, id string, _ time.Time, _ bool) (events.Detail, error) {
	if id != "e1" {
		return events.Detail{}, events.ErrNotFound
	}
	return events.Detail{Event: events.Event{ID: "e1"}, Raw: "<Event/>"}, nil
}

func TestEventsAPI(t *testing.T) {
	e := newEnv(t)
	fs := &fakeSearcher{}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Events: fs}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleViewer, "haslo-oli-12345", false)
	c := e.client("10.0.0.1")
	c.login("ola", "haslo-oli-12345")

	code, out, _ := c.do("GET", "/api/v1/events?q="+url.QueryEscape("code:4625 user:jan")+"&limit=10", nil)
	if code != 200 || len(out["events"].([]any)) != 10 || out["next"] == nil || fs.gotConds != 2 {
		t.Fatalf("wyszukiwanie: %d %v", code, out)
	}
	if !fs.gotTo.Equal(e.clock) || fs.gotTo.Sub(fs.gotFrom) != time.Hour {
		t.Fatalf("domyślny zakres: %v – %v", fs.gotFrom, fs.gotTo)
	}
	next := out["next"].(map[string]any)
	code, _, _ = c.do("GET", "/api/v1/events?before_ts="+url.QueryEscape(next["before_ts"].(string))+"&before_id="+next["before_id"].(string), nil)
	if code != 200 || fs.gotBefore == nil || fs.gotBefore.ID != "e9" {
		t.Fatalf("kursor: %d %+v", code, fs.gotBefore)
	}
	for q, want := range map[string]string{
		"?q=" + url.QueryEscape("code:abc"):                  "bad_query",
		"?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z": "bad_range",
		"?from=2026-03-01T00:00:00Z&to=2026-01-01T00:00:00Z": "bad_range",
		"?from=wczoraj": "bad_time",
	} {
		if code, out, _ := c.do("GET", "/api/v1/events"+q, nil); code != 400 || out["error"] != want {
			t.Errorf("%s: %d %v", q, code, out)
		}
	}
	if code, out, _ := c.do("GET", "/api/v1/events/histogram", nil); code != 200 || out["total"] != 3.0 || out["interval_s"] != 60.0 {
		t.Fatalf("histogram: %d %v", code, out)
	}
	ts := url.QueryEscape(e.clock.Format(time.RFC3339Nano))
	if code, out, _ := c.do("GET", "/api/v1/events/e1?ts="+ts, nil); code != 200 || out["event"].(map[string]any)["raw"] != "<Event/>" {
		t.Fatalf("szczegóły: %d %v", code, out)
	}
	if code, _, _ := c.do("GET", "/api/v1/events/nie-ma?ts="+ts, nil); code != 404 {
		t.Fatalf("brak zdarzenia: %d", code)
	}
	if code, out, _ := c.do("GET", "/api/v1/events/fields", nil); code != 200 || len(out["fields"].([]any)) < 10 {
		t.Fatalf("pola: %d %v", code, out)
	}

	// Bez połączenia z ClickHouse: czytelny błąd zamiast awarii.
	srv2 := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler)}
	srv2.now = srv.now
	e.h = srv2.Handler()
	if code, out, _ := c.do("GET", "/api/v1/events", nil); code != 503 || out["error"] != "events_disabled" {
		t.Fatalf("wyłączona wyszukiwarka: %d %v", code, out)
	}
}
