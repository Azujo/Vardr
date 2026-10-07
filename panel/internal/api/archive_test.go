package api

import (
	"context"
	"log/slog"
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
