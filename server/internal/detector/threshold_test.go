package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"siem/internal/alerts"
	"siem/server/internal/detect"
	"siem/server/internal/model"
)

const (
	bruteID    = "2feca112-9567-41b7-83de-92c2516f6cdc"
	sprayingID = "069fc75e-f818-4044-a674-eb48dda23f1c"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func repoEngine(t *testing.T) *Engine {
	t.Helper()
	rules, errs, err := detect.LoadDir("../../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	e := NewEngine()
	e.SetRules(rules)
	return e
}

// failed: nieudane logowanie 4625 na konto user z adresu ip.
func failed(n int, user, ip string, at time.Time) model.Event {
	return model.Event{ID: fmt.Sprintf("dc:Security:g0:%d", n), AgentID: "dc", Code: 4625, HostName: "dc01", Timestamp: at,
		SourceIP: ip, Fields: map[string]string{"winlog.channel": "Security", "TargetUserName": user, "TargetDomainName": "LAB",
			"IpAddress": ip}}
}

// run ocenia zdarzenia po jednym i zwraca trafienia danej reguły.
func run(e *Engine, rule string, evs ...model.Event) (hits []alerts.Hit, obs int) {
	for _, ev := range evs {
		h, o := e.Evaluate(&model.Batch{Events: []model.Event{ev}})
		obs += len(o)
		for _, x := range h {
			if x.RuleID == rule {
				hits = append(hits, x)
			}
		}
	}
	return hits, obs
}

func TestThresholdCount(t *testing.T) {
	e := repoEngine(t)
	var evs []model.Event
	for i := range 9 {
		evs = append(evs, failed(i, "jan", "10.0.0.5", t0.Add(time.Duration(i)*20*time.Second)))
	}
	if h, _ := run(e, bruteID, evs...); len(h) != 0 {
		t.Fatalf("9 prób – bez alertu, a jest %d trafień", len(h))
	}
	// Inne konto nie dolicza się do klucza „jan”.
	if h, _ := run(e, bruteID, failed(100, "ewa", "10.0.0.5", t0.Add(time.Minute))); len(h) != 0 {
		t.Fatal("inne konto przekroczyło próg")
	}
	h, _ := run(e, bruteID, failed(9, "JAN", "10.0.0.6", t0.Add(4*time.Minute)))
	if len(h) != 10 {
		t.Fatalf("10. próba: oczekiwano 10 trafień (całe okno), jest %d", len(h))
	}
	if h[0].GroupKey != "jan" || !strings.Contains(h[0].Summary, "próg: 10 zdarzeń w 5 min") ||
		!strings.Contains(h[0].Instructions, `10 nieudanych logowań na konto LAB\JAN`) || h[0].Suppress != time.Hour {
		t.Fatalf("trafienie: %+v", h[0])
	}
	// Kolejna próba w trakcie alertu – jedno trafienie (dopisanie do alertu).
	if h, _ := run(e, bruteID, failed(10, "jan", "10.0.0.5", t0.Add(30*time.Minute))); len(h) != 1 {
		t.Fatalf("kontynuacja: %d trafień", len(h))
	}
	// Ponowne dostarczenie zdarzenia – nic.
	if h, o := run(e, bruteID, failed(3, "jan", "10.0.0.5", t0)); len(h) != 0 || o != 0 {
		t.Fatalf("duplikat: %d trafień, %d obserwacji", len(h), o)
	}
}

func TestThresholdWindowAndOrder(t *testing.T) {
	e := repoEngine(t)
	// 10 prób rozłożonych na 9 × 40 s = 6 min – żadne okno 5 min nie ma 10.
	var spread []model.Event
	for i := range 10 {
		spread = append(spread, failed(i, "adam", "10.0.0.5", t0.Add(time.Duration(i)*40*time.Second)))
	}
	if h, _ := run(e, bruteID, spread...); len(h) != 0 {
		t.Fatalf("próby poza oknem: %d trafień", len(h))
	}
	// Zdarzenia spóźnione i w odwrotnej kolejności – liczy się czas zdarzenia.
	e = repoEngine(t)
	var rev []model.Event
	for i := 9; i >= 0; i-- {
		rev = append(rev, failed(i, "adam", "10.0.0.5", t0.Add(time.Duration(i)*10*time.Second)))
	}
	if h, _ := run(e, bruteID, rev...); len(h) != 10 {
		t.Fatalf("odwrotna kolejność: %d trafień", len(h))
	}
}

func TestThresholdDistinct(t *testing.T) {
	e := repoEngine(t)
	var evs []model.Event
	// To samo konto wiele razy (np. 4625 i 4771 tej samej próby) – jedna wartość.
	for i := range 6 {
		evs = append(evs, failed(i, "jan", "10.0.0.9", t0.Add(time.Duration(i)*time.Second)))
	}
	for i, u := range []string{"ewa", "adam", "ola"} {
		evs = append(evs, failed(10+i, u, "10.0.0.9", t0.Add(time.Minute)))
	}
	// Adres lokalny nie jest liczony.
	evs = append(evs, failed(20, "piotr", "-", t0.Add(time.Minute)))
	if h, _ := run(e, sprayingID, evs...); len(h) != 0 {
		t.Fatalf("4 różne konta – bez alertu, a jest %d", len(h))
	}
	h, _ := run(e, sprayingID, failed(30, "kasia", "10.0.0.9", t0.Add(2*time.Minute)))
	if len(h) != 10 || h[0].GroupKey != "10.0.0.9" || h[0].GroupFields["source.ip"] != "10.0.0.9" {
		t.Fatalf("spraying: %d trafień %+v", len(h), h)
	}
	if !strings.Contains(h[0].Summary, "5 różnych TargetUserName w 10 min") ||
		!strings.Contains(h[0].Instructions, "na 5\nróżnych kont: jan, ewa, adam, ola, kasia") {
		t.Fatalf("opis: %q\n%q", h[0].Summary, h[0].Instructions)
	}
}

func TestThresholdRestore(t *testing.T) {
	e := repoEngine(t)
	var saved []alerts.Observation
	for i := range 9 {
		_, o := e.Evaluate(&model.Batch{Events: []model.Event{failed(i, "jan", "10.0.0.5", t0.Add(time.Duration(i)*time.Second))}})
		saved = append(saved, o...)
	}
	// Nowy detektor (restart) ze stanem z bazy – 10. próba przekracza próg.
	e = repoEngine(t)
	// 9 prób w regule brute force i 9 w regule password spraying (ten sam adres).
	if n := e.RestoreThresholds(saved); n != 18 {
		t.Fatalf("odtworzono %d", n)
	}
	if h, _ := run(e, bruteID, failed(9, "jan", "10.0.0.5", t0.Add(time.Minute))); len(h) != 10 {
		t.Fatalf("po restarcie: %d trafień", len(h))
	}
	// Zmiana parametrów progu (inna sygnatura) – stary stan pomijany.
	for i := range saved {
		saved[i].Sig = "inny"
	}
	if n := repoEngine(t).RestoreThresholds(saved); n != 0 {
		t.Fatalf("stan o innej sygnaturze: %d", n)
	}
}

func TestThresholdRuleValidation(t *testing.T) {
	head := "title: t\nid: test-rule\nlevel: low\nlogsource:\n  product: windows\ndetection:\n  s:\n    EventID: 1\n  condition: s\nheimdall:\n"
	for name, y := range map[string]string{
		"próg 1":         "  threshold:\n    count: 1\n    window: 5m\n",
		"okno za długie": "  threshold:\n    count: 5\n    window: 48h\n",
		"brak okna":      "  threshold:\n    count: 5\n",
		"nieznane pole":  "  threshold:\n    count: 5\n    window: 5m\n    field: x\n",
	} {
		if _, err := detect.Parse([]byte(head+y), "x.yml"); err == nil {
			t.Errorf("%s: reguła powinna zostać odrzucona", name)
		}
	}
	r, err := detect.Parse([]byte(head+"  threshold:\n    count: 5\n    window: 2h\n"), "x.yml")
	if err != nil || time.Duration(r.Heimdall.Suppress) != 2*time.Hour {
		t.Fatalf("łączenie co najmniej na długość okna: %v %v", err, r)
	}
}
