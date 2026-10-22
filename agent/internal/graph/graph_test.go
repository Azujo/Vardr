// SPDX-License-Identifier: AGPL-3.0-or-later

package graph

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"siem/agent/internal/source"
	"siem/internal/entrasim"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func setup(t *testing.T, cfg entrasim.Config) (*entrasim.Sim, *Client, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)}
	sim := entrasim.New(cfg)
	sim.Now = clk.now
	srv := httptest.NewServer(sim)
	t.Cleanup(srv.Close)
	c := NewClient(Config{TenantID: "t1", ClientID: "app", ClientSecret: "sekret", LoginURL: srv.URL, GraphURL: srv.URL})
	c.now = clk.now
	return sim, c, clk
}

// collect czyta rekordy, dopóki przez 1,5 s nic nie przychodzi (ponowienie
// po 429 czeka 1 s – Retry-After).
func collect(out <-chan source.Record) []source.Record {
	var got []source.Record
	for {
		select {
		case r := <-out:
			got = append(got, r)
		case <-time.After(1500 * time.Millisecond):
			return got
		}
	}
}

// collectN czeka na n rekordów (najwyżej 15 s).
func collectN(out <-chan source.Record, n int) []source.Record {
	var got []source.Record
	deadline := time.After(15 * time.Second)
	for len(got) < n {
		select {
		case r := <-out:
			got = append(got, r)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestGraphSignIns(t *testing.T) {
	sim, c, clk := setup(t, entrasim.Config{Tenant: "t1", ClientID: "app", ClientSecret: "sekret", ThrottleN: 3})
	if _, err := sim.Scenario("spray", "", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	src := &Source{Client: c, Kind: SignIns, Interval: 50 * time.Millisecond, PageSize: 2, Lookback: 30 * time.Minute, Log: slog.New(slog.DiscardHandler), now: clk.now}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position, 1)
	go func() {
		pos, _ := src.Run(ctx, source.Position{}, out)
		done <- pos
	}()
	got := collectN(out, 9)
	if len(got) != 9 || len(collect(out)) != 0 { // 6 kont + administrator, test, backup; strony po 2, co trzecie zapytanie 429
		t.Fatalf("spray: %d rekordów", len(got))
	}
	keys := map[string]bool{}
	for i, r := range got {
		var d map[string]any
		if err := json.Unmarshal([]byte(r.Raw), &d); err != nil || d["ipAddress"] != "203.0.113.5" || r.Source != "entra:signin" ||
			r.Key == "" || r.Key != d["id"] || keys[r.Key] {
			t.Fatalf("rekord %d: %+v", i, r)
		}
		keys[r.Key] = true
		if i > 0 && r.RecordID <= got[i-1].RecordID {
			t.Fatal("numery rekordów nie rosną")
		}
	}
	// Kolejne odpytania nie powtarzają rekordów; nowy rekord – jeden.
	clk.add(time.Minute)
	sim.AddSignIn(entrasim.SignIn{User: "ewa", IP: "192.168.88.5"})
	more := collectN(out, 1)
	if len(more) != 1 || len(collect(out)) != 0 {
		t.Fatalf("kolejne odpytanie: %d", len(more))
	}
	keys[more[0].Key] = true
	cancel()
	pos := <-done

	// Restart z zapisanej pozycji: rekordy z zakładki wracają z tymi samymi kluczami (bez nowych zdarzeń).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _, _ = src.Run(ctx2, pos, out) }()
	// Zakładka 15 min obejmuje wszystkie 10 rekordów – te same klucze (te same zdarzenia).
	again := collectN(out, 10)
	if len(again) != 10 {
		t.Fatalf("po restarcie: %d rekordów", len(again))
	}
	for _, r := range again {
		if !keys[r.Key] {
			t.Fatalf("po restarcie rekord o nowym kluczu (duplikat zdarzenia): %+v", r)
		}
		if r.RecordID <= pos.RecordID-uint64(20*time.Minute/time.Microsecond) {
			t.Fatalf("numer rekordu po restarcie cofnął się poza zakładkę: %d < %d", r.RecordID, pos.RecordID)
		}
	}
}

// Rekord pojawiający się w API z opóźnieniem (starszy niż kursor) jest
// odczytany dzięki zakładce.
func TestGraphLateRecords(t *testing.T) {
	sim, c, clk := setup(t, entrasim.Config{Tenant: "t1", ClientID: "app", ClientSecret: "sekret", Latency: 10 * time.Minute})
	src := &Source{Client: c, Kind: SignIns, Interval: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler), now: clk.now}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 100)
	sim.AddSignIn(entrasim.SignIn{User: "jan", IP: "10.0.0.1", At: clk.now().Add(-time.Minute)})
	go func() { _, _ = src.Run(ctx, source.Position{}, out) }()
	first := collect(out)
	sim.AddSignIn(entrasim.SignIn{User: "ola", IP: "10.0.0.2"})
	clk.add(11 * time.Minute) // oba rekordy już widoczne (starsze niż kursor o mniej niż zakładka)
	second := collect(out)
	if len(first)+len(second) != 2 {
		t.Fatalf("rekordy z opóźnieniem: %d + %d", len(first), len(second))
	}
}

// Błąd uwierzytelnienia trafia do stanu źródła (panel: kanał „brak dostępu”).
func TestGraphAuthState(t *testing.T) {
	_, c, clk := setup(t, entrasim.Config{Tenant: "t1", ClientID: "app", ClientSecret: "inny"})
	states := make(chan string, 10)
	src := &Source{Client: c, Kind: SignIns, Interval: time.Hour, Log: slog.New(slog.DiscardHandler), now: clk.now,
		State: func(st, msg string) { states <- st + ": " + msg }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = src.Run(ctx, source.Position{}, make(chan source.Record, 1)) }()
	select {
	case s := <-states:
		if !strings.HasPrefix(s, "access_denied: ") || !strings.Contains(s, "invalid_client") {
			t.Fatalf("stan: %s", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("brak stanu źródła")
	}
}

func TestGraphAuthError(t *testing.T) {
	_, c, _ := setup(t, entrasim.Config{Tenant: "t1", ClientID: "app", ClientSecret: "inny"})
	var resp struct{}
	err := c.get(context.Background(), c.cfg.GraphURL+SignIns.Path, &resp)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("zły sekret: %v", err)
	}
}

func TestGraphAudits(t *testing.T) {
	sim, c, clk := setup(t, entrasim.Config{Tenant: "t1", ClientID: "app", ClientSecret: "sekret"})
	if _, err := sim.Scenario("admin-role", "jkowalski", ""); err != nil {
		t.Fatal(err)
	}
	src := &Source{Client: c, Kind: Audits, Interval: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler), now: clk.now}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan source.Record, 10)
	go func() { _, _ = src.Run(ctx, source.Position{}, out) }()
	got := collect(out)
	if len(got) != 1 || got[0].Source != "entra:audit" || got[0].Channel != "entra-audit" {
		t.Fatalf("zmiany w katalogu: %+v", got)
	}
}
