package detector

import (
	"strings"
	"testing"
	"time"

	"siem/internal/alerts"
	"siem/internal/contract"
)

func TestTamperCheck(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	beats := []alerts.TamperBeat{
		{ID: "agt-1", Host: "PC1", Group: "Stacje", LastSeen: now, Tokens: map[string]bool{"x": true}, Events: []contract.TamperRecord{
			{ID: "a", At: now.Add(-time.Minute), Kind: contract.TamperStop, User: `AZUJO\jan`},
			{ID: "b", At: now.Add(-time.Minute), Kind: contract.TamperStopToken, TokenID: "x"}, // legalne – bez alertu
			{ID: "c", At: now.Add(-8 * 24 * time.Hour), Kind: contract.TamperACL},              // za stare
			{ID: "d", At: now, Kind: contract.TamperUncleanExit},
			{ID: "e", At: now, Kind: "nieznany"},
		}},
		{ID: "agt-2", Host: "PC2", LastSeen: now.Add(-20 * time.Minute), Stopping: contract.TamperUpgrade},
		{ID: "agt-3", Host: "PC3", LastSeen: now.Add(-5 * time.Minute), Stopping: contract.TamperUpgrade}, // jeszcze czas
	}
	hits := TamperCheck(beats, now)
	// Zatrzymanie tokenem, którego panel nie wydał.
	forged := TamperCheck([]alerts.TamperBeat{{ID: "agt-9", LastSeen: now, Events: []contract.TamperRecord{
		{ID: "f", At: now, Kind: contract.TamperUninstallTok, TokenID: "obcy"}}}}, now)
	if len(forged) != 1 || forged[0].Level != "high" || !strings.Contains(forged[0].Summary, "nieznany panelowi") {
		t.Fatalf("podrobiony token: %+v", forged)
	}
	if len(hits) != 3 {
		t.Fatalf("%d alertów: %+v", len(hits), hits)
	}
	if hits[0].EventID != "tamper:agt-1:a" || hits[0].Level != "high" || hits[0].UserName != `AZUJO\jan` ||
		!strings.Contains(hits[0].Summary, "bez tokenu") {
		t.Errorf("%+v", hits[0])
	}
	if hits[1].Level != "medium" || hits[2].AgentID != "agt-2" || !strings.Contains(hits[2].Summary, "nie wrócił") {
		t.Errorf("%+v %+v", hits[1], hits[2])
	}
	// Ten sam stan – te same identyfikatory (baza odrzuca powtórki).
	if again := TamperCheck(beats, now.Add(time.Minute)); again[0].EventID != hits[0].EventID || again[2].EventID != hits[2].EventID {
		t.Error("identyfikatory zdarzeń niestabilne")
	}
}
