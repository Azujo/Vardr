package api

import (
	"strings"
	"testing"
	"time"

	"siem/panel/internal/api/store"
)

// Terminy NIS2: 24 h, 72 h od stwierdzenia, sprawozdanie końcowe miesiąc od
// zgłoszenia (przed jego wysłaniem – od terminu zgłoszenia).
func TestDeadlines(t *testing.T) {
	aware := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	x := store.Incident{Significant: true, AwareAt: &aware}
	d := deadlines(x, nil)
	if len(d) != 3 || !d[0].Due.Equal(aware.Add(24*time.Hour)) || !d[1].Due.Equal(aware.Add(72*time.Hour)) ||
		!d[2].Due.Equal(time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("terminy: %+v", d)
	}
	sent := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	d = deadlines(x, []store.IncidentReport{{Kind: "notification", SubmittedAt: &sent}})
	if d[1].SubmittedAt == nil || !d[2].Due.Equal(time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("po zgłoszeniu: %+v", d)
	}
	if len(deadlines(store.Incident{Significant: false, AwareAt: &aware}, nil)) != 0 {
		t.Fatal("incydent niepoważny – bez terminów")
	}
}

func TestReportDraft(t *testing.T) {
	aware := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	x := store.Incident{ID: 7, Title: "Ransomware na DC", Severity: "critical", Status: "contained", Malicious: "yes",
		CrossBorder: "no", Significant: true, AwareAt: &aware, IOCs: "1.2.3.4"}
	als := []store.IncidentAlert{{RuleTitle: "Wyczyszczenie dziennika", Level: "high", HostName: "dc01", UserName: "jan",
		FirstSeen: aware, LastSeen: aware.Add(time.Hour), Summary: "komputer dc01"}}
	ew := reportDraft("early_warning", x, als, aware)
	if !strings.Contains(ew, "Wczesne ostrzeżenie – incydent #7") || !strings.Contains(ew, "złośliwego: tak") || strings.Contains(ew, "Wskaźniki") {
		t.Fatalf("wczesne ostrzeżenie:\n%s", ew)
	}
	fin := reportDraft("final", x, als, aware)
	for _, want := range []string{"1.2.3.4", "dc01", "Wyczyszczenie dziennika", "pierwotna przyczyna", "[uzupełnij]"} {
		if !strings.Contains(fin, want) {
			t.Errorf("sprawozdanie końcowe bez %q:\n%s", want, fin)
		}
	}
}
