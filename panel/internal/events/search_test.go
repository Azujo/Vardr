package events

import (
	"context"
	"os"
	"testing"
	"time"
)

// Test na prawdziwym ClickHouse z danymi laboratorium (zdarzenia agentów
// i generatora). Uruchamiany tylko z SIEM_TEST_CH_ADDR/USER/PASSWORD.
func TestSearchClickHouse(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test na ClickHouse")
	}
	// Ten sam limit czasu co w panelu – sterownik zamienia go na
	// max_execution_time, który konto siem_panel ogranicza.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Open(ctx, addr, os.Getenv("SIEM_TEST_CH_USER"), os.Getenv("SIEM_TEST_CH_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	to := time.Now().Add(time.Minute)
	from := to.Add(-7 * 24 * time.Hour)

	all, _ := Parse("")
	page1, err := s.Search(ctx, all, from, to, nil, 50)
	if err != nil || len(page1) == 0 {
		t.Fatalf("wyszukiwanie: %d %v", len(page1), err)
	}
	for i := 1; i < len(page1); i++ {
		if page1[i].Timestamp.After(page1[i-1].Timestamp) {
			t.Fatal("wyniki nie są posortowane od najnowszych")
		}
	}
	last := page1[len(page1)-1]
	page2, err := s.Search(ctx, all, from, to, &Cursor{Timestamp: last.Timestamp, ID: last.ID}, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range page1 {
		seen[e.ID] = true
	}
	for _, e := range page2 {
		if seen[e.ID] {
			t.Fatalf("zdarzenie %s na dwóch stronach", e.ID)
		}
	}

	q, _ := Parse("code:4624 dataset:windows.security")
	logons, err := s.Search(ctx, q, from, to, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range logons {
		if e.Code != 4624 || e.Action != "logged-in" {
			t.Fatalf("filtr: %+v", e)
		}
	}
	t.Logf("4624: %d wyników, przykład: %s %s %s %s", len(logons), e0(logons).Host, e0(logons).User, e0(logons).IP, e0(logons).Action)

	if len(logons) > 0 && logons[0].IP != "" {
		ipq, _ := Parse("ip:" + logons[0].IP)
		byIP, err := s.Search(ctx, ipq, from, to, nil, 5)
		if err != nil || len(byIP) == 0 || byIP[0].IP != logons[0].IP {
			t.Fatalf("filtr ip: %v %v", byIP, err)
		}
	}

	txt, _ := Parse(`"KERNELBASE.dll"`)
	if r, err := s.Search(ctx, txt, from, to, nil, 5); err != nil {
		t.Fatalf("tekst: %v", err)
	} else {
		t.Logf("tekst KERNELBASE.dll: %d wyników", len(r))
	}

	inj, _ := Parse(`user:x' OR 1=1 -- "'); DROP TABLE siem.events; --"`)
	if r, err := s.Search(ctx, inj, from, to, nil, 5); err != nil || len(r) != 0 {
		t.Fatalf("próba wstrzyknięcia: %d %v", len(r), err)
	}

	buckets, step, total, err := s.Histogram(ctx, all, from, to)
	if err != nil || len(buckets) == 0 || total == 0 {
		t.Fatalf("histogram: %d %v %d %v", len(buckets), step, total, err)
	}
	t.Logf("histogram: %d słupków po %v, razem %d", len(buckets), step, total)

	d, err := s.Get(ctx, page1[0].ID, page1[0].Timestamp)
	if err != nil || d.ID != page1[0].ID || len(d.Fields) == 0 {
		t.Fatalf("szczegóły: %+v %v", d.Event, err)
	}
	if _, err := s.Get(ctx, "nie-ma-takiego", page1[0].Timestamp); err != ErrNotFound {
		t.Fatalf("brak zdarzenia: %v", err)
	}
}

func e0(l []Event) Event {
	if len(l) == 0 {
		return Event{}
	}
	return l[0]
}
