// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test na prawdziwym PostgreSQL (SIEM_TEST_PG_URL, pusta baza testowa).
func TestPostgresAlerts(t *testing.T) {
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
	if again, err := db.Migrate(ctx); err != nil || len(again) != 0 {
		t.Fatalf("ponowne migracje: %v %v", again, err)
	}
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	single := func(ev string, at time.Time) Hit {
		return Hit{RuleID: "r-log", RuleTitle: "Wyczyszczenie dziennika", Level: "high", Engine: "stream",
			GroupKey: ev, EventID: ev, EventTime: at, HostName: "dc01", Summary: "komputer dc01",
			I18n: map[string]AlertText{"en": {Title: "Log cleared", Summary: "computer dc01"}}}
	}
	grouped := func(ev string, at time.Time) Hit {
		return Hit{RuleID: "r-ps", RuleTitle: "PowerShell", Level: "medium", Engine: "stream",
			GroupFields: map[string]string{"Computer": "pc1"}, GroupKey: "pc1", Suppress: time.Hour, EventID: ev, EventTime: at}
	}

	res, err := db.Record(ctx, []Hit{single("e1", t0), grouped("p1", t0), grouped("p2", t0.Add(10*time.Minute))}, nil)
	if err != nil || res.NewAlerts != 2 || res.Merged != 1 {
		t.Fatalf("pierwszy zapis: %+v %v", res, err)
	}
	// Ponowne dostarczenie tych samych zdarzeń – bez zmian.
	res, err = db.Record(ctx, []Hit{single("e1", t0), grouped("p1", t0)}, nil)
	if err != nil || res.Duplicates != 2 || res.NewAlerts != 0 {
		t.Fatalf("ponowne dostarczenie: %+v %v", res, err)
	}
	// Trafienie poza oknem łączenia – nowy alert.
	res, _ = db.Record(ctx, []Hit{grouped("p3", t0.Add(3*time.Hour))}, nil)
	if res.NewAlerts != 1 {
		t.Fatalf("poza oknem: %+v", res)
	}
	list, total, err := db.Alerts(ctx, Filter{Status: "open"})
	if err != nil || len(list) != 3 || total != 3 {
		t.Fatalf("lista: %d/%d %v", len(list), total, err)
	}
	var ps Alert
	for _, a := range list {
		if a.RuleID == "r-ps" && a.Hits == 2 {
			ps = a
		}
	}
	if ps.ID == 0 || !ps.LastSeen.Equal(t0.Add(10*time.Minute)) || ps.GroupFields["Computer"] != "pc1" {
		t.Fatalf("połączony alert: %+v", ps)
	}
	for _, a := range list {
		if a.RuleID == "r-log" {
			if en := a.Text("en"); en.Title != "Log cleared" || en.Summary != "computer dc01" || a.Text("de").Title != "Wyczyszczenie dziennika" {
				t.Fatalf("tłumaczenie alertu: %+v", a.I18n)
			}
		}
	}
	if evs, _ := db.AlertEvents(ctx, ps.ID, 10); len(evs) != 2 {
		t.Fatalf("zdarzenia alertu: %+v", evs)
	}
	// Outbox: po jednym wpisie na nowy alert; rezerwacja nie wydaje ich drugi raz.
	// „Teraz” z prawdziwego zegara: baza ustawia termin wysyłki w outboxie na now().
	now := time.Now().UTC().Add(4 * time.Hour)
	p, err := db.ClaimOutbox(ctx, now, 10)
	if err != nil || len(p) != 3 {
		t.Fatalf("outbox: %d %v", len(p), err)
	}
	if again, _ := db.ClaimOutbox(ctx, now, 10); len(again) != 0 {
		t.Fatalf("zarezerwowane wpisy wydane ponownie: %d", len(again))
	}
	_ = db.MarkSent(ctx, p[0].OutboxID, now)
	_ = db.MarkFailed(ctx, p[1].OutboxID, "HTTP 500", now.Add(time.Minute))
	if retry, _ := db.ClaimOutbox(ctx, now.Add(3*time.Minute), 10); len(retry) != 2 {
		t.Fatalf("ponowienie po terminie: %d", len(retry))
	}
	// Zamknięcie alertu: kolejne trafienie z tym kluczem tworzy nowy alert.
	if _, err := db.SetStatus(ctx, ps.ID, "closed", "adam", "test", "false_positive", now); err != nil {
		t.Fatal(err)
	}
	res, _ = db.Record(ctx, []Hit{grouped("p4", t0.Add(15*time.Minute))}, nil)
	if res.NewAlerts != 1 {
		t.Fatalf("po zamknięciu: %+v", res)
	}
	if k, err := db.KnownEvents(ctx, "r-ps", []string{"p1", "p2", "brak"}); err != nil || len(k) != 2 || !k["p1"] {
		t.Fatalf("zdarzenia w alertach: %v %v", k, err)
	}
	// Zamknięcie po rozwiązaniu (np. powrót agenta) z powiadomieniem w outboxie.
	hb := Hit{RuleID: "hb", RuleTitle: "Utrata łączności", Level: "high", Engine: "system", GroupKey: "agt-1@1",
		EventID: "heartbeat:agt-1:1", EventTime: t0, AgentID: "agt-1"}
	if _, err := db.Record(ctx, []Hit{hb}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := db.CloseOpen(ctx, "hb", "agt-1@", "Agent wrócił", true, now); err != nil || n != 1 {
		t.Fatalf("zamknięcie: %d %v", n, err)
	}
	var kinds []string
	for _, p := range mustClaim(t, db, now.Add(time.Hour)) {
		if p.Alert.RuleID == "hb" {
			kinds = append(kinds, p.Kind)
		}
	}
	if strings.Join(kinds, ",") != "new,resolved" {
		t.Fatalf("outbox alertu i rozwiązania: %v", kinds)
	}
	// Triage: przypisanie, notatka, zamknięcie wielu naraz, oś czasu, filtry, powiązane.
	if a, err := db.Assign(ctx, ps.ID, "ewa", "adam", now); err != nil || a.Assignee != "ewa" {
		t.Fatalf("przypisanie: %+v %v", a, err)
	}
	if err := db.AddNote(ctx, ps.ID, "ewa", "sprawdzone z użytkownikiem", now); err != nil {
		t.Fatal(err)
	}
	if err := db.AddNote(ctx, 999999, "ewa", "x", now); err != ErrNotFound {
		t.Fatalf("notatka do nieistniejącego alertu: %v", err)
	}
	mine, n, _ := db.Alerts(ctx, Filter{Assignee: "ewa"})
	if n != 1 || len(mine) != 1 || mine[0].ID != ps.ID {
		t.Fatalf("filtr przypisania: %d %+v", n, mine)
	}
	if _, n, _ := db.Alerts(ctx, Filter{Text: "PowerSh", Level: "medium"}); n < 1 {
		t.Fatalf("filtr tekstu i poziomu: %d", n)
	}
	if _, n, _ := db.Alerts(ctx, Filter{Level: "critical"}); n != 0 {
		t.Fatalf("filtr poziomu od krytycznego: %d", n)
	}
	// Filtr po regułach (technika ATT&CK): lista reguł; pusta lista – nic.
	if l, n, _ := db.Alerts(ctx, Filter{RuleIDs: []string{ps.RuleID}}); n < 1 || l[0].RuleID != ps.RuleID {
		t.Fatalf("filtr reguł: %d", n)
	}
	if _, n, _ := db.Alerts(ctx, Filter{RuleIDs: []string{}}); n != 0 {
		t.Fatalf("pusta lista reguł: %d", n)
	}
	counts, err := db.AlertCountsByRule(ctx, time.Time{})
	if err != nil || counts[ps.RuleID].Total < 1 || counts[ps.RuleID].Last == nil {
		t.Fatalf("liczby alertów reguł: %+v %v", counts, err)
	}
	open, _, _ := db.Alerts(ctx, Filter{Status: "open"})
	var ids []int64
	for _, a := range open {
		ids = append(ids, a.ID)
	}
	changed, err := db.SetStatusMany(ctx, append(ids, 999999), "acknowledged", "adam", "", "", now)
	if err != nil || len(changed) == 0 {
		t.Fatalf("zmiana wielu: %d %v", len(changed), err)
	}
	if again, _ := db.SetStatusMany(ctx, ids, "acknowledged", "adam", "", "", now); len(again) != 0 {
		t.Fatalf("ponowna zmiana na ten sam stan: %d", len(again))
	}
	act, err := db.Activity(ctx, ps.ID)
	if err != nil || len(act) < 3 || act[0].Kind != "status" || act[1].Kind != "assign" || act[2].Kind != "note" {
		t.Fatalf("oś czasu: %+v %v", act, err)
	}
	rel, err := db.Related(ctx, Alert{ID: -1, HostName: "dc01", FirstSeen: t0, LastSeen: t0}, 24*time.Hour, 10)
	if err != nil || len(rel) == 0 {
		t.Fatalf("powiązane: %d %v", len(rel), err)
	}
	// Burza alertów: wstrzymanie ponad limit i wiadomość zbiorcza.
	var storm []Hit
	for i := range 4 {
		storm = append(storm, Hit{RuleID: "r-storm", RuleTitle: "Burza", Level: "medium", Engine: "stream",
			GroupKey: fmt.Sprint("s", i), EventID: fmt.Sprint("s", i), EventTime: t0, HostName: fmt.Sprint("pc", i)})
	}
	if _, err := db.Record(ctx, storm, nil); err != nil {
		t.Fatal(err)
	}
	var stormOut []Pending
	for _, p := range mustClaim(t, db, now.Add(2*time.Hour)) {
		if p.Alert.RuleID == "r-storm" {
			stormOut = append(stormOut, p)
		}
	}
	if len(stormOut) != 4 {
		t.Fatalf("outbox burzy: %d", len(stormOut))
	}
	_ = db.MarkSent(ctx, stormOut[0].OutboxID, now)
	for _, p := range stormOut[1:] {
		if err := db.Hold(ctx, p.OutboxID, now); err != nil {
			t.Fatal(err)
		}
	}
	if per, err := db.SentPerRule(ctx, now.Add(-time.Minute)); err != nil || per["r-storm"] != 1 {
		t.Fatalf("wysłane na regułę: %v %v", per, err)
	}
	if d, _ := db.DueDigests(ctx, now.Add(-time.Minute)); len(d) != 0 {
		t.Fatalf("zbiorcza przed czasem: %+v", d)
	}
	d, err := db.DueDigests(ctx, now)
	if err != nil || len(d) != 1 || d[0].Count != 3 || d[0].HostCount != 3 || d[0].Levels[0] != "medium" {
		t.Fatalf("zbiorcza: %+v %v", d, err)
	}
	if err := db.MarkDigested(ctx, "r-storm", d[0].Upto, now); err != nil {
		t.Fatal(err)
	}
	if d, _ := db.DueDigests(ctx, now.Add(time.Hour)); len(d) != 0 {
		t.Fatalf("zbiorcza po oznaczeniu: %+v", d)
	}
	// Punkt kontrolny silnika zapytań: tylko w przód.
	if _, err := db.RecordIndex(ctx, nil, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _ = db.RecordIndex(ctx, nil, t0)
	if cp, ok, err := db.IndexCheckpoint(ctx); err != nil || !ok || !cp.Equal(t0.Add(time.Hour)) {
		t.Fatalf("punkt kontrolny: %v %v %v", cp, ok, err)
	}
	// Stan progów: zapis z trafieniami, bez duplikatów, odczyt i czyszczenie.
	obs := func(ev string, exp time.Time) Observation {
		return Observation{RuleID: "r-bf", Sig: "10|5m0s||TargetUserName", GroupKey: "jan",
			GroupFields: map[string]string{"TargetUserName": "jan"}, EventID: ev, EventTime: t0, HostName: "dc01", ExpiresAt: exp}
	}
	if _, err := db.Record(ctx, nil, []Observation{obs("b1", now.Add(time.Hour)), obs("b2", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Record(ctx, nil, []Observation{obs("b1", now.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if o, err := db.Observations(ctx, now); err != nil || len(o) != 1 || o[0].GroupFields["TargetUserName"] != "jan" {
		t.Fatalf("stan progów: %+v %v", o, err)
	}
	if n, err := db.PruneObservations(ctx, now); err != nil || n != 1 {
		t.Fatalf("czyszczenie stanu progów: %d %v", n, err)
	}
	// Reguły i podsumowanie.
	if err := db.SyncRules(ctx, []RuleInfo{{ID: "r-ps", Title: "PowerShell", Level: "medium", File: "a.yml", Source: "x", Mode: "both", Enabled: true,
		Threshold: &Threshold{Count: 10, WindowS: 300}}},
		[]RuleError{{File: "zla.yml", Error: "brak title"}}, now); err != nil {
		t.Fatal(err)
	}
	// 3 otwarte z początku testu + 4 z burzy alertów.
	if s, err := db.Summarize(ctx, now); err != nil || s.Open != 7 || s.Rules != 1 || s.RuleErrs != 1 {
		t.Fatalf("podsumowanie: %+v %v", s, err)
	}
	if r, err := db.Rule(ctx, "r-ps"); err != nil || r.Threshold == nil || r.Threshold.WindowS != 300 {
		t.Fatalf("próg reguły: %+v %v", r.Threshold, err)
	}
	// Wersje: ta sama treść – bez nowej wersji, zmiana – v2; ustawienie z panelu.
	info := RuleInfo{ID: "r-ps", Title: "PowerShell", Level: "medium", File: "a.yml", Source: "x", Mode: "both", Enabled: true, FileEnabled: true}
	_ = db.SyncRules(ctx, []RuleInfo{info}, nil, now)
	info.Source = "x2"
	_ = db.SyncRules(ctx, []RuleInfo{info}, nil, now.Add(time.Minute))
	vs, err := db.RuleVersions(ctx, "r-ps")
	if err != nil || len(vs) != 2 || vs[0].Version != 2 || vs[0].Source != "x2" {
		t.Fatalf("wersje reguły: %+v %v", vs, err)
	}
	if err := db.SetOverride(ctx, "r-ps", Override{Enabled: false, Reason: "fałszywe alarmy", ChangedBy: "adam", ChangedAt: now}); err != nil {
		t.Fatal(err)
	}
	ov, sig, err := db.RuleOverrides(ctx)
	if err != nil || ov["r-ps"].Enabled || sig == "" {
		t.Fatalf("ustawienia reguł: %+v %q %v", ov, sig, err)
	}
	if r, _ := db.Rule(ctx, "r-ps"); r.Override == nil || r.Override.ChangedBy != "adam" || r.Version != 2 || !r.FileEnabled {
		t.Fatalf("reguła z ustawieniem: %+v", r)
	}
	if ok, err := db.ClearOverride(ctx, "r-ps"); !ok || err != nil {
		t.Fatalf("usunięcie ustawienia: %v %v", ok, err)
	}
	// Tryb próbny: trafienia sumowane godzinami i komputerami, wyniki od
	// początku próby; trafienia reguły spoza próby są pomijane.
	if err := db.SetOverride(ctx, "r-ps", Override{Trial: true, Enabled: true, Reason: "ocena", ChangedBy: "adam", ChangedAt: now}); err != nil {
		t.Fatal(err)
	}
	if ov, _, _ := db.RuleOverrides(ctx); !ov["r-ps"].Trial || ov["r-ps"].Enabled {
		t.Fatalf("próba: %+v", ov["r-ps"])
	}
	h0 := now.Truncate(time.Hour)
	th := []TrialHit{
		{RuleID: "r-ps", Hour: h0, Host: "pc1", Hits: 2, First: now, Last: now, SampleEventID: "e1", SampleSummary: "s1"},
		{RuleID: "r-ps", Hour: h0, Host: "pc2", Hits: 1, First: now, Last: now, SampleEventID: "e2", SampleSummary: "s2"},
		{RuleID: "r-none", Hour: h0, Host: "pc1", Hits: 9, First: now, Last: now, SampleEventID: "x", SampleSummary: "x"},
	}
	if err := db.RecordTrial(ctx, th); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordTrial(ctx, []TrialHit{{RuleID: "r-ps", Hour: h0, Host: "pc1", Hits: 3, First: now,
		Last: now.Add(time.Minute), SampleEventID: "e3", SampleSummary: "s3"}}); err != nil {
		t.Fatal(err)
	}
	ts, err := db.TrialStats(ctx)
	if err != nil || len(ts) != 1 || ts[0].Hits != 6 || ts[0].Hosts != 2 || ts[0].TopHosts[0].Host != "pc1" ||
		ts[0].TopHosts[0].Hits != 5 || ts[0].SampleEventID != "e3" || len(ts[0].Days) != 1 {
		t.Fatalf("wyniki próby: %+v %v", ts, err)
	}
	// Ponowne ustawienie próby nie zeruje; nowa próba po wyjściu – od zera.
	_ = db.SetOverride(ctx, "r-ps", Override{Trial: true, Reason: "dalej", ChangedBy: "adam", ChangedAt: now})
	if ts, _ := db.TrialStats(ctx); ts[0].Hits != 6 {
		t.Fatalf("próba trwa: %+v", ts)
	}
	_ = db.SetOverride(ctx, "r-ps", Override{Enabled: false, Reason: "koniec", ChangedBy: "adam", ChangedAt: now})
	_ = db.SetOverride(ctx, "r-ps", Override{Trial: true, Reason: "znowu", ChangedBy: "adam", ChangedAt: now})
	if ts, _ := db.TrialStats(ctx); ts[0].Hits != 0 || len(ts[0].TopHosts) != 0 {
		t.Fatalf("nowa próba: %+v", ts)
	}
	if n, err := db.PruneTrial(ctx, now.Add(48*time.Hour)); err != nil || n != 0 {
		t.Fatalf("sprzątanie prób: %d %v", n, err)
	}
	if ok, err := db.ClearOverride(ctx, "r-ps"); !ok || err != nil {
		t.Fatalf("usunięcie próby: %v %v", ok, err)
	}
	// Reguły z panelu (kreator korelacji): zapis, zmiana (podpis się zmienia), usunięcie.
	if _, err := db.PanelRule(ctx, "corr-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("brak reguły z panelu: %v", err)
	}
	if err := db.SavePanelRule(ctx, "corr-x", "title: a", "adam", now); err != nil {
		t.Fatal(err)
	}
	_, sig1, _ := db.PanelRules(ctx)
	if err := db.SavePanelRule(ctx, "corr-x", "title: b", "ewa", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	prs, sig2, err := db.PanelRules(ctx)
	if err != nil || len(prs) != 1 || prs[0].Source != "title: b" || prs[0].CreatedBy != "adam" || prs[0].UpdatedBy != "ewa" || sig1 == sig2 {
		t.Fatalf("reguły z panelu: %+v %q %q %v", prs, sig1, sig2, err)
	}
	if ok, err := db.DeletePanelRule(ctx, "corr-x"); !ok || err != nil {
		t.Fatalf("usunięcie reguły z panelu: %v %v", ok, err)
	}
	// Retencja: zamknięte alerty (z oś czasu i zdarzeniami) znikają, otwarte zostają.
	_, openBefore, _ := db.Alerts(ctx, Filter{Status: "open"})
	pr, err := db.Prune(ctx, now.Add(24*time.Hour), now.Add(24*time.Hour), 2)
	if err != nil || pr.Alerts == 0 || pr.Outbox == 0 {
		t.Fatalf("retencja: %+v %v", pr, err)
	}
	if _, n, _ := db.Alerts(ctx, Filter{Status: "closed"}); n != 0 {
		t.Fatalf("po retencji zostały zamknięte alerty: %d", n)
	}
	if _, n, _ := db.Alerts(ctx, Filter{Status: "open"}); n != openBefore {
		t.Fatalf("retencja usunęła otwarte alerty: %d → %d", openBefore, n)
	}
	if act, _ := db.Activity(ctx, ps.ID); len(act) != 0 {
		t.Fatalf("oś czasu usuniętego alertu: %d", len(act))
	}

	// Zapis zbiorczy (etap 8): w jednej paczce seria łączy się w jeden alert,
	// trafienie poza oknem tworzy drugi, a powtórzone zdarzenie jest duplikatem.
	gk := func(ev string, at time.Time) Hit {
		h := grouped(ev, at)
		h.RuleID, h.GroupKey, h.GroupFields = "r-batch", "pc9", map[string]string{"Computer": "pc9"}
		return h
	}
	tb := t0.Add(48 * time.Hour)
	batch := []Hit{gk("b1", tb), gk("b2", tb.Add(30*time.Minute)), gk("b2", tb.Add(30*time.Minute)),
		gk("b3", tb.Add(80*time.Minute)), gk("b4", tb.Add(5*time.Hour)), gk("b5", tb.Add(-20*time.Minute))}
	res, err = db.Record(ctx, batch, nil)
	if err != nil || res.NewAlerts != 2 || res.Merged != 3 || res.Duplicates != 1 {
		t.Fatalf("paczka: %+v %v", res, err)
	}
	got, _, _ := db.Alerts(ctx, Filter{Status: "open", RuleID: "r-batch"})
	byHits := map[int]Alert{}
	for _, a := range got {
		byHits[a.Hits] = a
	}
	if a := byHits[4]; len(got) != 2 || a.ID == 0 || !a.FirstSeen.Equal(tb.Add(-20*time.Minute)) || !a.LastSeen.Equal(tb.Add(80*time.Minute)) {
		t.Fatalf("alerty paczki: %+v", got)
	}
	if evs, _ := db.AlertEvents(ctx, byHits[4].ID, 10); len(evs) != 4 {
		t.Fatalf("zdarzenia alertu paczki: %d", len(evs))
	}
	// Następna paczka dołącza do istniejącego alertu (zapytanie o otwarte alerty).
	res, _ = db.Record(ctx, []Hit{gk("b6", tb.Add(90*time.Minute))}, nil)
	if res.Merged != 1 || res.NewAlerts != 0 {
		t.Fatalf("dołączenie: %+v", res)
	}
	// Trafienie „tylko licznik”: podbija licznik i czas bez dołączania zdarzenia;
	// bez otwartego alertu – zwykłe trafienie.
	co := gk("b7", tb.Add(100*time.Minute))
	co.CountOnly, co.Count = true, 3
	other := gk("c1", tb.Add(100*time.Minute))
	other.GroupKey, other.CountOnly = "pc10", true
	if res, err = db.Record(ctx, []Hit{co, other}, nil); err != nil || res.Merged != 1 || res.NewAlerts != 1 {
		t.Fatalf("tylko licznik: %+v %v", res, err)
	}
	keys, err := db.OpenAlerts(ctx, "r-batch", tb)
	if err != nil || len(keys) != 2 || !keys["pc9"].Equal(tb.Add(5*time.Hour)) { // najnowszy z dwóch alertów pc9
		t.Fatalf("otwarte alerty: %v %v", keys, err)
	}
	a, _ := db.Alert(ctx, byHits[4].ID)
	if evs, _ := db.AlertEvents(ctx, a.ID, 10); a.Hits != 8 || len(evs) != 5 {
		t.Fatalf("alert po trafieniu „tylko licznik”: %d trafień, %d zdarzeń", a.Hits, len(evs))
	}
	if again, _ := db.Record(ctx, []Hit{other}, nil); again.Duplicates != 0 || again.Merged != 1 {
		t.Fatalf("drugie „tylko licznik”: %+v", again)
	}

	// Równoległe zapisy (silniki bez wspólnej blokady w detektorze): ten sam
	// klucz i różne zdarzenia – jeden alert (bez blokady kluczy powstawało
	// kilka); te same zdarzenia w odwrotnej kolejności – bez dubli
	// i bez zakleszczeń.
	tp := tb.Add(24 * time.Hour)
	parallel := func(key string, batch func(g int) []Hit) {
		t.Helper()
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, 8)
		for g := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hs := batch(g)
				<-start
				if _, err := db.Record(ctx, hs, nil); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("zapis równoległy %s: %v", key, err)
		}
	}
	par := func(key, ev string, at time.Time) Hit {
		h := gk(ev, at)
		h.RuleID, h.GroupKey = "r-par", key
		return h
	}
	for round := range 10 {
		key := fmt.Sprintf("pc-par-%d", round)
		parallel(key, func(g int) []Hit {
			var hs []Hit
			for i := range 10 {
				hs = append(hs, par(key, fmt.Sprintf("%s-%d-%d", key, g, i), tp.Add(time.Duration(i)*time.Second)))
			}
			return hs
		})
	}
	parallel("pc-shared", func(g int) []Hit {
		var hs []Hit
		for i := range 20 {
			hs = append(hs, par("pc-shared", fmt.Sprintf("sh-%d", i), tp.Add(time.Duration(i)*time.Second)))
		}
		if g%2 == 1 {
			slices.Reverse(hs)
		}
		return hs
	})
	got, _, _ = db.Alerts(ctx, Filter{Status: "open", RuleID: "r-par", Limit: 100})
	perKey := map[string][]int{}
	for _, a := range got {
		perKey[a.GroupKey] = append(perKey[a.GroupKey], a.Hits)
	}
	for k, hits := range perKey {
		want := 80
		if k == "pc-shared" {
			want = 20
		}
		if len(hits) != 1 || hits[0] != want {
			t.Fatalf("zapis równoległy %s: alerty z trafieniami %v (oczekiwany jeden z %d)", k, hits, want)
		}
	}
	if len(perKey) != 11 {
		t.Fatalf("zapis równoległy: %d kluczy", len(perKey))
	}

	// Powiązane po osobie: konto Entra (UPN) i konto AD tej samej osoby.
	ti := tp.Add(24 * time.Hour)
	entra := single("id-entra", ti)
	entra.HostName, entra.UserName, entra.Identity = "", "jan@azujo.pl", "jan"
	ad := single("id-ad", ti.Add(time.Hour))
	ad.HostName, ad.UserName, ad.Identity = "pc7", `AZUJO\jan`, "jan"
	if _, err := db.Record(ctx, []Hit{entra, ad}, nil); err != nil {
		t.Fatal(err)
	}
	got, _, _ = db.Alerts(ctx, Filter{Status: "open", RuleID: "r-log", Limit: 100})
	var ea Alert
	for _, a := range got {
		if a.FirstEventID == "id-entra" {
			ea = a
		}
	}
	rel, err = db.Related(ctx, ea, 24*time.Hour, 10)
	if err != nil || ea.UserIdentity != "jan" || len(rel) != 1 || rel[0].FirstEventID != "id-ad" {
		t.Fatalf("powiązane po osobie: %+v %v %v", ea, rel, err)
	}
}

func mustClaim(t *testing.T, db *PG, now time.Time) []Pending {
	t.Helper()
	p, err := db.ClaimOutbox(ctx0, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var ctx0 = context.Background()
