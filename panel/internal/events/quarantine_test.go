package events

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Zapytania kwarantanny na prawdziwym ClickHouse (dane laboratorium;
// SIEM_TEST_CH_ADDR/USER/PASSWORD jak w TestSearchClickHouse).
func TestQuarantineClickHouse(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test na ClickHouse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Open(ctx, addr, os.Getenv("SIEM_TEST_CH_USER"), os.Getenv("SIEM_TEST_CH_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	f := QuarantineFilter{From: time.Now().Add(-90 * 24 * time.Hour)}
	groups, entries, total, err := s.QuarantineOverview(ctx, f, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Skip("kwarantanna laboratorium jest pusta")
	}
	var sum uint64
	for _, g := range groups {
		sum += g.Count
	}
	if sum != total || total < uint64(len(entries)) {
		t.Fatalf("grupy %d, razem %d, wpisy %d", sum, total, len(entries))
	}
	var pick *QuarantineEntry
	for i, e := range entries {
		if strings.HasPrefix(e.Source, "syslog:") || strings.HasPrefix(e.Source, "wineventlog:") {
			pick = &entries[i]
			break
		}
	}
	if pick == nil {
		t.Skip("brak wpisów do ponownego przetworzenia")
	}
	// Filtr po wskazanych wpisach (tablica jako parametr), źródle i powodzie.
	f.EventIDs, f.Source, f.Reason = []string{pick.EventID, "nie-ma-takiego"}, pick.Source[:4], strings.ToUpper(pick.Reason[:5])
	items, err := s.QuarantineItems(ctx, f, 10)
	if err != nil || len(items) != 1 || items[0].EventID != pick.EventID || items[0].Raw == "" || items[0].AgentID != pick.AgentID {
		t.Fatalf("wpisy do przetworzenia: %+v %v", items, err)
	}
	f.Agent = "inny-agent"
	if items, err := s.QuarantineItems(ctx, f, 10); err != nil || len(items) != 0 {
		t.Fatalf("filtr agenta: %d %v", len(items), err)
	}
}

// Podpowiedź domen i osoby na danych laboratorium.
func TestPeopleClickHouse(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test na ClickHouse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Open(ctx, addr, os.Getenv("SIEM_TEST_CH_USER"), os.Getenv("SIEM_TEST_CH_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	from := time.Now().Add(-7 * 24 * time.Hour)
	ds, err := s.DomainsSeen(ctx, from)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if strings.ContainsAny(d.Domain, `\@`) || d.Domain != strings.ToLower(d.Domain) {
			t.Fatalf("domena: %+v", d)
		}
	}
	t.Logf("domeny: %+v", ds)
	ps, err := s.People(ctx, from, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("osób: %d", len(ps))
}
