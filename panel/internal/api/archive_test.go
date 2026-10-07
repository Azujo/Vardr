package api

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"siem/internal/urd"
	"siem/panel/internal/api/store"
)

type fakeArchive struct {
	o           urd.Overview
	err         error
	requestedBy string
	exports     []urd.ExportJob
	replays     []urd.ReplayJob
}

func (f *fakeArchive) Overview(context.Context) (urd.Overview, error) { return f.o, f.err }
func (f *fakeArchive) RecentManifests(context.Context, int) ([]urd.ManifestRecord, error) {
	return []urd.ManifestRecord{{Seq: 1, SHA256: urd.GenesisPrev, PrevSHA256: urd.GenesisPrev}}, f.err
}
func (f *fakeArchive) Verifications(context.Context, int) ([]urd.Verification, error) {
	return nil, f.err
}
func (f *fakeArchive) RequestVerify(_ context.Context, by string, _ time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.requestedBy = by
	return nil
}

func TestCompliance(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	st := &urd.ArchiverState{HeartbeatAt: now.Add(-time.Minute), VerifyEveryS: 6 * 3600}
	ok := &urd.Verification{OK: true, FinishedAt: now.Add(-time.Hour)}
	for _, c := range []struct {
		name string
		o    urd.Overview
		want string
	}{
		{"brak archiwizatora", urd.Overview{}, complianceNotConfigured},
		{"zgodne", urd.Overview{State: st, LastVerification: ok}, complianceOK},
		{"niezgodności", urd.Overview{State: st, LastVerification: &urd.Verification{OK: false, FinishedAt: now}}, complianceProblems},
		{"bez weryfikacji", urd.Overview{State: st}, complianceNeverVerified},
		{"stara weryfikacja", urd.Overview{State: st, LastVerification: &urd.Verification{OK: true, FinishedAt: now.Add(-14 * time.Hour)}}, complianceStale},
		{"brak miejsca", urd.Overview{State: &urd.ArchiverState{HeartbeatAt: now, VerifyEveryS: 3600, Paused: "mało miejsca", DiskFreeBytes: 1, DiskTotalBytes: 100}, LastVerification: ok}, complianceDiskFull},
		{"mało miejsca", urd.Overview{State: &urd.ArchiverState{HeartbeatAt: now, VerifyEveryS: 3600, DiskFreeBytes: 10, DiskTotalBytes: 100}, LastVerification: ok}, complianceDiskLow},
		{"archiwizator milczy", urd.Overview{State: &urd.ArchiverState{HeartbeatAt: now.Add(-5 * time.Minute), VerifyEveryS: 3600}, LastVerification: ok}, complianceDown},
	} {
		if got := compliance(c.o, now); got != c.want {
			t.Errorf("%s: %s, oczekiwano %s", c.name, got, c.want)
		}
	}
}

func TestArchiveAPI(t *testing.T) {
	e := newEnv(t)
	fa := &fakeArchive{o: urd.Overview{State: &urd.ArchiverState{HeartbeatAt: e.clock, VerifyEveryS: 3600}}}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Archive: fa}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleViewer, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	viewer, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	viewer.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	code, out, _ := viewer.do("GET", "/api/v1/archive", nil)
	if code != 200 || out["compliance"] != complianceNeverVerified || out["archiver_running"] != true || len(out["manifests"].([]any)) != 1 {
		t.Fatalf("stan: %d %v", code, out)
	}
	if code, _, _ := viewer.do("POST", "/api/v1/archive/verify", nil); code != 403 {
		t.Fatalf("zlecenie weryfikacji tylko dla administratora: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/verify", nil); code != 202 || fa.requestedBy != "adam" {
		t.Fatalf("zlecenie: %d %q", code, fa.requestedBy)
	}
	if !slices.Contains(e.st.actions(), "archive_verify_requested") {
		t.Fatalf("brak wpisu audytu: %v", e.st.actions())
	}

	fa.err = urd.ErrNotConfigured
	if code, out, _ := viewer.do("GET", "/api/v1/archive", nil); code != 200 || out["compliance"] != complianceNotConfigured {
		t.Fatalf("bez archiwum: %d %v", code, out)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/verify", nil); code != 409 {
		t.Fatalf("zlecenie bez archiwum: %d", code)
	}
}

func (f *fakeArchive) CreateExport(_ context.Context, by, reason string, from, to time.Time) (urd.ExportJob, error) {
	if f.err != nil {
		return urd.ExportJob{}, f.err
	}
	j := urd.ExportJob{ID: int64(len(f.exports) + 1), RequestedBy: by, Reason: reason, From: from, To: to, Status: urd.ExportPending}
	f.exports = append(f.exports, j)
	return j, nil
}
func (f *fakeArchive) Exports(context.Context, int) ([]urd.ExportJob, error) { return f.exports, f.err }
func (f *fakeArchive) ExportByID(_ context.Context, id int64) (urd.ExportJob, error) {
	for _, j := range f.exports {
		if j.ID == id {
			return j, nil
		}
	}
	return urd.ExportJob{}, urd.ErrExportNotFound
}

func TestArchiveExportAPI(t *testing.T) {
	e := newEnv(t)
	fa := &fakeArchive{}
	dir := t.TempDir()
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Archive: fa, ExportDir: dir}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	from := e.clock.Add(-30 * time.Hour)
	body := map[string]any{"from": from, "to": from.Add(90 * time.Minute), "reason": "kontrola KSC"}
	if code, _, _ := analyst.do("POST", "/api/v1/archive/exports", body); code != 403 {
		t.Fatalf("eksport tylko dla administratora: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/exports", map[string]any{"from": from, "to": from.Add(time.Hour), "reason": "x"}); code != 400 {
		t.Fatalf("powód jest obowiązkowy: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/exports", map[string]any{"from": from, "to": from.Add(40 * 24 * time.Hour), "reason": "za długo"}); code != 400 {
		t.Fatalf("limit 31 dni: %d", code)
	}
	code, out, _ := admin.do("POST", "/api/v1/archive/exports", body)
	if code != 202 {
		t.Fatalf("zlecenie: %d %v", code, out)
	}
	j := fa.exports[0]
	if !j.From.Equal(from.UTC().Truncate(time.Hour)) || j.To.Sub(j.From) != 2*time.Hour || j.RequestedBy != "adam" {
		t.Fatalf("zakres zaokrąglony do pełnych godzin: %+v", j)
	}
	if code, _, _ := admin.do("GET", "/api/v1/archive/exports/1/download", nil); code != 409 {
		t.Fatalf("niegotowy eksport: %d", code)
	}
	fa.exports[0].Status = urd.ExportDone
	fa.exports[0].FileName = urd.ExportName(fa.exports[0])
	if err := os.WriteFile(filepath.Join(dir, fa.exports[0].FileName), []byte("tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, resp := admin.do("GET", "/api/v1/archive/exports/1/download", nil)
	if code != 200 || resp.Header.Get("Content-Disposition") == "" {
		t.Fatalf("pobranie: %d", code)
	}
	fa.exports[0].FileName = "../../etc/passwd"
	if code, _, _ := admin.do("GET", "/api/v1/archive/exports/1/download", nil); code != 409 {
		t.Fatalf("nazwa spoza wzorca nie może zostać wydana: %d", code)
	}
	acts := e.st.actions()
	if !slices.Contains(acts, "archive_export_requested") || !slices.Contains(acts, "archive_export_downloaded") {
		t.Fatalf("audyt: %v", acts)
	}
}

func (f *fakeArchive) CreateReplay(_ context.Context, by, reason string, from, to time.Time, agents []string) (urd.ReplayJob, error) {
	j := urd.ReplayJob{ID: int64(len(f.replays) + 1), RequestedBy: by, Reason: reason, From: from, To: to, Agents: agents, Status: urd.ReplayPending}
	f.replays = append(f.replays, j)
	return j, f.err
}
func (f *fakeArchive) Replays(context.Context, int) ([]urd.ReplayJob, error) { return f.replays, f.err }

func TestArchiveReplayAPI(t *testing.T) {
	e := newEnv(t)
	fa := &fakeArchive{}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Archive: fa}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")

	from := e.clock.Add(-10 * 24 * time.Hour)
	body := map[string]any{"from": from, "to": from.Add(3 * time.Hour), "agents": []string{" agt-1 ", "agt-1", ""}, "reason": "analiza incydentu"}
	if code, _, _ := analyst.do("POST", "/api/v1/archive/replays", body); code != 403 {
		t.Fatalf("odtworzenie tylko dla administratora: %d", code)
	}
	if code, out, _ := admin.do("POST", "/api/v1/archive/replays", body); code != 202 {
		t.Fatalf("zlecenie: %d %v", code, out)
	}
	if j := fa.replays[0]; len(j.Agents) != 1 || j.Agents[0] != "agt-1" || j.RequestedBy != "adam" {
		t.Fatalf("agenci po oczyszczeniu: %+v", j)
	}
	if code, out, _ := admin.do("GET", "/api/v1/archive/replays", nil); code != 200 || len(out["replays"].([]any)) != 1 {
		t.Fatalf("lista: %d %v", code, out)
	}
	if !slices.Contains(e.st.actions(), "archive_replay_requested") {
		t.Fatalf("audyt: %v", e.st.actions())
	}
}
