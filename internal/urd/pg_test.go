package urd

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// Test integracyjny na prawdziwym PostgreSQL (SIEM_TEST_PG_URL, pusta baza
// testowa): pełny cykl archiwum z katalogiem w schemacie urd.
func TestPostgresCatalog(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := OpenPG(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.pool.Exec(ctx, "DROP SCHEMA IF EXISTS urd CASCADE"); err != nil {
		t.Fatal(err)
	}
	if applied, err := db.Migrate(ctx); err != nil || len(applied) == 0 {
		t.Fatalf("migracje: %v %v", applied, err)
	}
	if again, err := db.Migrate(ctx); err != nil || len(again) != 0 {
		t.Fatalf("ponowne migracje: %v %v", again, err)
	}
	release, err := db.LockWriter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	now := time.Date(2026, 10, 7, 10, 5, 0, 0, time.UTC)
	a := New(t.TempDir(), db)
	a.Now = func() time.Time { return now }
	for h := range 3 {
		w, err := a.OpenSegment()
		if err != nil {
			t.Fatal(err)
		}
		for r := range 4 {
			if err := w.Add(RecordMeta{Agent: "agt", Batch: string(rune('a' + h*4 + r)), ReceivedAt: now}, []byte("dane")); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	if open, err := db.OpenSegments(ctx); err != nil || len(open) != 3 {
		t.Fatalf("otwarte segmenty: %d %v", len(open), err)
	}
	if n, err := a.Seal(ctx); err != nil || n != 3 {
		t.Fatalf("seal: %d %v", n, err)
	}
	if open, _ := db.OpenSegments(ctx); len(open) != 0 {
		t.Fatalf("segmenty powinny mieć manifest: %d", len(open))
	}
	v := a.Verify(ctx, VerifyOptions{})
	if !v.OK || v.Manifests != 3 || v.Records != 12 {
		t.Fatalf("weryfikacja: %+v", v)
	}
	if id, err := db.SaveVerification(ctx, v); err != nil || id == 0 {
		t.Fatalf("zapis weryfikacji: %d %v", id, err)
	}
	if got, ok, err := db.LastVerification(ctx); err != nil || !ok || !got.OK || len(got.Problems) != 0 {
		t.Fatalf("odczyt weryfikacji: %+v %v", got, err)
	}

	// Retencja: najstarsza godzina wygasa, łańcuch zostaje ciągły.
	now = now.Add(-30 * time.Minute) // 12:35 → granica 11:35 przy retencji 1 h
	if n, err := a.Expire(ctx, time.Hour); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if v := a.Verify(ctx, VerifyOptions{}); !v.OK || v.Manifests != 2 {
		t.Fatalf("po retencji: %+v", v)
	}
	recent, err := db.RecentManifests(ctx, 10)
	if err != nil || len(recent) != 3 || recent[2].ExpiredAt == nil {
		t.Fatalf("ostatnie manifesty: %+v %v", recent, err)
	}

	// Manipulacja w bazie: usunięcie wpisu ze środka łańcucha.
	if _, err := db.pool.Exec(ctx, "DELETE FROM urd.manifests WHERE seq = 2"); err != nil {
		t.Fatal(err)
	}
	if v := a.Verify(ctx, VerifyOptions{}); v.OK {
		t.Fatal("usunięcie manifestu z bazy powinno zostać wykryte")
	}
	// Spójność segmentów z manifestem jest pilnowana transakcją.
	if err := db.AddManifest(ctx, ManifestRecord{Seq: 9, Hour: now.Add(24 * time.Hour), SHA256: GenesisPrev,
		PrevSHA256: GenesisPrev, Body: []byte("{}")}, []string{"segments/nie/istnieje.urd"}); err == nil {
		t.Fatal("manifest z nieznanym segmentem powinien zostać odrzucony")
	}
	if _, ok, _ := db.LastManifest(ctx); !ok {
		t.Fatal("brak ostatniego manifestu")
	}
	if m, _, _ := db.LastManifest(ctx); m.Seq != 3 {
		t.Fatalf("odrzucony manifest nie może zostać zapisany: %d", m.Seq)
	}

	// Stan dla panelu i zlecenia weryfikacji.
	if err := db.RequestVerify(ctx, "adam", now); err != ErrNotConfigured {
		t.Fatalf("zlecenie bez stanu archiwizatora: %v", err)
	}
	st := ArchiverState{Version: "t", RetentionDays: 30, SegmentMaxMB: 64, SegmentMaxAgeS: 30, VerifyEveryS: 21600,
		StartedAt: now, HeartbeatAt: now}
	if err := db.SaveState(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := db.RequestVerify(ctx, "adam", now); err != nil {
		t.Fatal(err)
	}
	st.HeartbeatAt = now.Add(time.Minute)
	if err := db.SaveState(ctx, st); err != nil { // nie kasuje zlecenia
		t.Fatal(err)
	}
	if by, ok, err := db.TakeVerifyRequest(ctx); err != nil || !ok || by != "adam" {
		t.Fatalf("odbiór zlecenia: %q %v %v", by, ok, err)
	}
	if _, ok, err := db.TakeVerifyRequest(ctx); err != nil || ok {
		t.Fatalf("zlecenie odebrane dwa razy: %v %v", ok, err)
	}
	o, err := db.Overview(ctx)
	if err != nil || o.State == nil || !o.State.HeartbeatAt.Equal(st.HeartbeatAt) || o.LastVerification == nil ||
		o.Summary.ManifestsTotal != 2 || o.Summary.Manifests != 1 || o.Summary.Batches != 4 {
		t.Fatalf("przegląd: %+v %v", o, err)
	}
	if vs, err := db.Verifications(ctx, 5); err != nil || len(vs) != 1 || !vs[0].OK {
		t.Fatalf("historia weryfikacji: %+v %v", vs, err)
	}

	// Zlecenia eksportu.
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	if _, err := db.CreateExport(ctx, "adam", "x", from, from.Add(time.Hour), nil); err == nil {
		t.Fatal("baza powinna odrzucić zbyt krótki powód")
	}
	if _, err := db.CreateExport(ctx, "adam", "kontrola", from, from.Add(40*24*time.Hour), nil); err == nil {
		t.Fatal("baza powinna odrzucić zakres ponad 31 dni")
	}
	ex, err := db.CreateExport(ctx, "adam", "kontrola KSC", from, from.Add(time.Hour), nil)
	if err != nil || ex.Status != ExportPending {
		t.Fatalf("zlecenie: %+v %v", ex, err)
	}
	got, ok, err := db.ClaimExport(ctx)
	if err != nil || !ok || got.ID != ex.ID || got.Status != ExportRunning {
		t.Fatalf("pobranie zlecenia: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := db.ClaimExport(ctx); ok {
		t.Fatal("zlecenie pobrane dwa razy")
	}
	got.Status, got.FileName, got.SHA256, got.Bytes = ExportDone, ExportName(got), strings.Repeat("a", 64), 10
	if err := db.FinishExport(ctx, got); err != nil {
		t.Fatal(err)
	}
	if list, err := db.Exports(ctx, 10); err != nil || len(list) != 1 || list[0].FinishedAt == nil {
		t.Fatalf("lista eksportów: %+v %v", list, err)
	}
	if names, err := db.ExpireExports(ctx, time.Now().Add(time.Hour)); err != nil || len(names) != 1 || names[0] != got.FileName {
		t.Fatalf("wygaszanie: %v %v", names, err)
	}
	if _, err := db.ExportByID(ctx, 999); err != ErrExportNotFound {
		t.Fatalf("brak eksportu: %v", err)
	}

	// Zlecenia odtworzenia.
	rp, err := db.CreateReplay(ctx, "adam", "analiza incydentu", from, from.Add(time.Hour), []string{"agt-1"})
	if err != nil || rp.Status != ReplayPending || len(rp.Agents) != 1 {
		t.Fatalf("zlecenie odtworzenia: %+v %v", rp, err)
	}
	if _, err := db.CreateReplay(ctx, "adam", "bez agentów", from, from.Add(time.Hour), nil); err != nil {
		t.Fatalf("odtworzenie wszystkich agentów: %v", err)
	}
	claimed, ok, err := db.ClaimReplay(ctx)
	if err != nil || !ok || claimed.ID != rp.ID || claimed.Status != ReplayRunning {
		t.Fatalf("pobranie odtworzenia: %+v %v %v", claimed, ok, err)
	}
	if err := db.ReplayProgress(ctx, claimed.ID, ReplayStats{Batches: 3, Skipped: 1, Bytes: 100}); err != nil {
		t.Fatal(err)
	}
	if n, err := db.FailInterruptedReplays(ctx); err != nil || n != 1 {
		t.Fatalf("przerwane odtworzenia: %d %v", n, err)
	}
	if list, err := db.Replays(ctx, 10); err != nil || len(list) != 2 || list[1].Status != ReplayFailed || list[1].Batches != 3 {
		t.Fatalf("lista odtworzeń: %+v %v", list, err)
	}

	// Panel przed pierwszym uruchomieniem archiwizatora.
	if _, err := db.pool.Exec(ctx, "DROP SCHEMA urd CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Overview(ctx); err != ErrNotConfigured {
		t.Fatalf("brak schematu: %v", err)
	}
}

// Polityka archiwum: zlecenia z panelu, karencja osłabień, granice, anulowanie.
func TestPostgresPolicy(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := OpenPG(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.pool.Exec(ctx, "DROP SCHEMA IF EXISTS urd CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	b := PolicyBounds{MinRetentionDays: 30, MaxRetentionDays: 365}
	if _, _, err := db.ProcessPolicyChanges(ctx, b, time.Hour, now); err != ErrNoPolicy {
		t.Fatalf("bez polityki: %v", err)
	}
	pol, created, err := db.InitPolicy(ctx, Policy{Enabled: true, RetentionDays: 90, UpdatedAt: now, UpdatedBy: "konfiguracja serwera"})
	if err != nil || !created || pol.RetentionDays != 90 {
		t.Fatalf("założenie polityki: %+v %v %v", pol, created, err)
	}
	if pol, created, _ := db.InitPolicy(ctx, Policy{Enabled: true, RetentionDays: 7, UpdatedAt: now}); created || pol.RetentionDays != 90 {
		t.Fatal("ponowny start nie może nadpisać polityki z panelu")
	}
	change := func(enabled bool, days int, agents ...string) PolicyChange {
		t.Helper()
		c, err := db.CreatePolicyChange(ctx, PolicyChange{RequestedBy: "adam", Reason: "zmiana testowa", Enabled: enabled,
			RetentionDays: days, ExcludedAgents: agents})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Wzmocnienie – od razu.
	c1 := change(true, 120)
	changed, cur, err := db.ProcessPolicyChanges(ctx, b, time.Hour, now)
	if err != nil || len(changed) != 1 || changed[0].Status != PolicyApplied || cur.RetentionDays != 120 || *cur.ChangeID != c1.ID {
		t.Fatalf("wzmocnienie: %+v %+v %v", changed, cur, err)
	}
	// Osłabienie – po karencji.
	c2 := change(false, 120, "agt-x")
	changed, cur, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now)
	if len(changed) != 1 || changed[0].Status != PolicyScheduled || !cur.Enabled ||
		!slices.Equal(changed[0].Weakening, []string{WeakenDisable, WeakenAgents}) {
		t.Fatalf("osłabienie: %+v %+v", changed, cur)
	}
	if sc, _ := db.ScheduledChange(ctx); sc == nil || sc.ID != c2.ID {
		t.Fatalf("zaplanowana zmiana: %+v", sc)
	}
	if changed, cur, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now.Add(30*time.Minute)); len(changed) != 0 || !cur.Enabled {
		t.Fatalf("przed końcem karencji: %+v", changed)
	}
	changed, cur, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now.Add(61*time.Minute))
	if len(changed) != 1 || changed[0].Status != PolicyApplied || cur.Enabled || !slices.Equal(cur.ExcludedAgents, []string{"agt-x"}) {
		t.Fatalf("po karencji: %+v %+v", changed, cur)
	}
	// Anulowanie zaplanowanego osłabienia.
	c3 := change(false, 60)
	_, _, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now.Add(2*time.Hour))
	if _, err := db.CancelPolicyChange(ctx, c3.ID, "ewa", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CancelPolicyChange(ctx, c3.ID, "ewa", now.Add(2*time.Hour)); err != ErrPolicyChangeClosed {
		t.Fatalf("ponowne anulowanie: %v", err)
	}
	changed, cur, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now.Add(4*time.Hour))
	if len(changed) != 1 || changed[0].Status != PolicyCancelled || cur.RetentionDays != 120 {
		t.Fatalf("anulowanie: %+v %+v", changed, cur)
	}
	// Retencja spoza granic – odrzucenie; starsze otwarte zlecenie – zastąpione.
	c4 := change(true, 200)
	c5 := change(true, 10)
	changed, cur, _ = db.ProcessPolicyChanges(ctx, b, time.Hour, now.Add(5*time.Hour))
	st := map[int64]string{}
	for _, c := range changed {
		st[c.ID] = c.Status
	}
	if st[c4.ID] != PolicySuperseded || st[c5.ID] != PolicyRejected || cur.RetentionDays != 120 {
		t.Fatalf("zastąpienie i odrzucenie: %v %+v", st, cur)
	}
	if hist, err := db.PolicyChanges(ctx, 10); err != nil || len(hist) != 5 || hist[0].ID != c5.ID || hist[0].Error == "" {
		t.Fatalf("historia: %+v %v", hist, err)
	}
	// Przynależność do grup obserwowana przez archiwizator.
	since := now.Add(-time.Hour)
	if err := db.SaveGroupMembership(ctx, map[string]Membership{"agt-a": {Group: 3, Since: since}}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveGroupMembership(ctx, map[string]Membership{"agt-a": {Group: 4, Since: now}}); err != nil {
		t.Fatal(err)
	}
	if m, err := db.GroupMembership(ctx); err != nil || len(m) != 1 || m["agt-a"].Group != 4 || !m["agt-a"].Since.Equal(now) {
		t.Fatalf("przynależność: %+v %v", m, err)
	}
	// Grupy agentów z tabel panelu – w pustej bazie testowej ich nie ma.
	if _, _, ok, err := db.SourceGroups(ctx); err != nil || ok {
		t.Fatalf("grupy bez tabel panelu: %v %v", ok, err)
	}
}

// Obsługa niezgodności na PostgreSQL: pliki zapisane po „zrzucie” (wpisy
// usunięte z bazy) wracają do spisu; zlecenia i lista nieznanych plików.
func TestPostgresRecovery(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := OpenPG(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.pool.Exec(ctx, "DROP SCHEMA IF EXISTS urd CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 6, 50, 0, 0, time.UTC)
	a := New(t.TempDir(), db)
	a.Now = func() time.Time { return now }
	seg := func() Segment {
		w, err := a.OpenSegment()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Add(RecordMeta{Agent: "agt", ReceivedAt: now}, []byte("dane")); err != nil {
			t.Fatal(err)
		}
		s, err := w.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	seg()
	now = now.Add(15 * time.Minute) // 07:05
	if n, err := a.Seal(ctx); err != nil || n != 1 {
		t.Fatalf("seal 06: %d %v", n, err)
	}
	dumpAt := now
	// Po „zrzucie”: zamknięcie godziny 07 i segment w 08 – potem przywrócenie
	// bazy usuwa ich wpisy (symulacja: DELETE).
	seg()
	now = now.Add(time.Hour) // 08:05
	if n, err := a.Seal(ctx); err != nil || n != 1 {
		t.Fatalf("seal 07: %d %v", n, err)
	}
	late := seg()
	if _, err := db.pool.Exec(ctx, `DELETE FROM urd.manifests WHERE seq = 2; DELETE FROM urd.segments WHERE hour >= '2026-10-19 07:00Z'`); err != nil {
		t.Fatal(err)
	}
	v := a.Verify(ctx, VerifyOptions{})
	if v.OK || len(v.Unknown) != 3 {
		t.Fatalf("nieznane: %+v", v.Unknown)
	}
	vid, err := db.SaveVerification(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := db.LastVerification(ctx); len(got.Unknown) != 3 {
		t.Fatalf("odczyt nieznanych: %v", got.Unknown)
	}
	// Zlecenie po przywróceniu (jak restore.sh) i decyzja administratora.
	if _, err := db.pool.Exec(ctx, `INSERT INTO urd.recoveries (kind, requested_by, reason, backup, window_from, window_to)
		VALUES ('restore', 'adam (panel)', 'test', 'vardr-x.tar.gpg', $1, $2)`, dumpAt.Add(-10*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	id, err := db.RequestRecovery(ctx, "quarantine", "adam", "plik testowy", []string{"segments/x"}, vid)
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	pending, err := db.PendingRecoveries(ctx)
	if err != nil || len(pending) != 2 || pending[0].Kind != "restore" || pending[0].WindowFrom == nil || *pending[1].VerificationID != vid {
		t.Fatalf("oczekujące: %+v %v", pending, err)
	}
	res, err := a.Run(ctx, pending[0])
	if err != nil || len(res.Manifests) != 1 || len(res.Segments) != 1 || res.Segments[0].Path != late.Path {
		t.Fatalf("uzgodnienie: %+v %v", res, err)
	}
	if err := db.FinishRecovery(ctx, pending[0].ID, true, &res, "", now); err != nil {
		t.Fatal(err)
	}
	if v := a.Verify(ctx, VerifyOptions{}); !v.OK {
		t.Fatalf("po uzgodnieniu: %v", v.Problems)
	}
	all, err := db.Recoveries(ctx, 10)
	if err != nil || len(all) != 2 || all[1].Result == nil || len(all[1].Result.Manifests) != 1 || all[0].ProcessedAt != nil {
		t.Fatalf("historia: %+v %v", all, err)
	}
}
