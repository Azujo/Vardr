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
	changes     []urd.PolicyChange
	members     map[string]urd.Membership
}

func (f *fakeArchive) GroupMembership(context.Context) (map[string]urd.Membership, error) {
	return f.members, f.err
}
func (f *fakeArchive) PolicyChanges(context.Context, int) ([]urd.PolicyChange, error) {
	return f.changes, f.err
}
func (f *fakeArchive) CreatePolicyChange(_ context.Context, c urd.PolicyChange) (urd.PolicyChange, error) {
	c.ID, c.Status = int64(len(f.changes)+1), urd.PolicyPending
	f.changes = append(f.changes, c)
	return c, f.err
}
func (f *fakeArchive) CancelPolicyChange(_ context.Context, id int64, by string, at time.Time) (urd.PolicyChange, error) {
	for i, c := range f.changes {
		if c.ID == id && c.Status == urd.PolicyPending && c.CancelledAt == nil {
			f.changes[i].CancelledAt, f.changes[i].CancelledBy = &at, by
			return f.changes[i], nil
		}
	}
	return urd.PolicyChange{}, urd.ErrPolicyChangeClosed
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
		{"archiwum wyłączone", urd.Overview{State: st, LastVerification: ok, Policy: &urd.Policy{Enabled: false}}, complianceDisabled},
		{"zaplanowane osłabienie", urd.Overview{State: st, LastVerification: ok, Policy: &urd.Policy{Enabled: true},
			ScheduledChange: &urd.PolicyChange{ID: 3}}, complianceScheduled},
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

func (f *fakeArchive) CreateExport(_ context.Context, by, reason string, from, to time.Time, agents []string) (urd.ExportJob, error) {
	if f.err != nil {
		return urd.ExportJob{}, f.err
	}
	j := urd.ExportJob{ID: int64(len(f.exports) + 1), RequestedBy: by, Reason: reason, From: from, To: to, Status: urd.ExportPending,
		Agents: agents}
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

func TestArchivePolicyAPI(t *testing.T) {
	e := newEnv(t)
	fa := &fakeArchive{o: urd.Overview{
		State:  &urd.ArchiverState{HeartbeatAt: e.clock, VerifyEveryS: 3600, MinRetentionDays: 30, MaxRetentionDays: 365, PolicyGraceS: 86400},
		Policy: &urd.Policy{Enabled: true, RetentionDays: 90, ExcludedGroups: []int64{}, ExcludedAgents: []string{}}}}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), Archive: fa}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("ola", store.RoleAnalyst, "haslo-oli-12345", false)
	e.addUser("adam", store.RoleAdmin, "haslo-adama-123", false)
	analyst, admin := e.client("10.0.0.1"), e.client("10.0.0.2")
	analyst.login("ola", "haslo-oli-12345")
	admin.login("adam", "haslo-adama-123")
	e.st.agents = map[string]store.Agent{"agt-a": {ID: "agt-a", Hostname: "PC-A"}, "agt-b": {ID: "agt-b", Hostname: "PC-B"}}

	code, out, _ := analyst.do("GET", "/api/v1/archive/policy", nil)
	if code != 200 || out["policy"].(map[string]any)["retention_days"] != 90.0 || len(out["unarchived"].([]any)) != 0 {
		t.Fatalf("polityka: %d %v", code, out)
	}
	body := func(enabled bool, days int, agents []string, pw string) map[string]any {
		return map[string]any{"enabled": enabled, "retention_days": days, "excluded_agents": agents, "excluded_groups": []int64{},
			"reason": "zmiana testowa", "password": pw}
	}
	if code, _, _ := analyst.do("POST", "/api/v1/archive/policy", body(true, 120, nil, "")); code != 403 {
		t.Fatalf("zmiana tylko dla administratora: %d", code)
	}
	// Wzmocnienie (dłuższa retencja) – bez hasła.
	if code, out, _ := admin.do("POST", "/api/v1/archive/policy", body(true, 120, nil, "")); code != 202 || len(out["weakening"].([]any)) != 0 {
		t.Fatalf("wydłużenie retencji: %d %v", code, out)
	}
	// Retencja spoza granic z konfiguracji serwera.
	if code, _, _ := admin.do("POST", "/api/v1/archive/policy", body(true, 7, nil, "haslo-adama-123")); code != 400 {
		t.Fatalf("retencja poniżej minimum: %d", code)
	}
	// Osłabienia wymagają hasła.
	for _, b := range []map[string]any{body(false, 90, nil, ""), body(true, 60, nil, ""), body(true, 90, []string{"agt-b"}, "")} {
		if code, out, _ := admin.do("POST", "/api/v1/archive/policy", b); code != 403 || out["error"] != "reauth_required" {
			t.Fatalf("osłabienie bez hasła: %d %v", code, out)
		}
	}
	if code, out, _ := admin.do("POST", "/api/v1/archive/policy", body(false, 90, nil, "zle-haslo")); code != 403 || out["error"] != "reauth_failed" {
		t.Fatalf("błędne hasło: %d %v", code, out)
	}
	code, out, _ = admin.do("POST", "/api/v1/archive/policy", body(true, 90, []string{"agt-b", " agt-b "}, "haslo-adama-123"))
	if code != 202 || out["weakening"].([]any)[0] != urd.WeakenAgents {
		t.Fatalf("wyłączenie agenta z hasłem: %d %v", code, out)
	}
	last := fa.changes[len(fa.changes)-1]
	if !last.Reauth || !slices.Equal(last.ExcludedAgents, []string{"agt-b"}) || last.RequestedBy != "adam" {
		t.Fatalf("zlecenie: %+v", last)
	}
	acts := e.st.actions()
	if !slices.Contains(acts, "archive_policy_change_requested") || !slices.Contains(acts, "reauth_failed") {
		t.Fatalf("audyt: %v", acts)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/policy/changes/2/cancel", nil); code != 200 {
		t.Fatalf("anulowanie: %d", code)
	}
	if code, _, _ := admin.do("POST", "/api/v1/archive/policy/changes/2/cancel", nil); code != 409 {
		t.Fatalf("ponowne anulowanie: %d", code)
	}

	// Źródła bez archiwizacji według obowiązującej polityki.
	fa.o.Policy.ExcludedAgents = []string{"agt-b"}
	code, out, _ = admin.do("GET", "/api/v1/archive/policy", nil)
	un := out["unarchived"].([]any)
	if code != 200 || len(un) != 1 || un[0].(map[string]any)["agent_id"] != "agt-b" || un[0].(map[string]any)["reason"] != "agent" {
		t.Fatalf("źródła bez archiwum: %d %v", code, out)
	}
	// Agent przeniesiony do wyłączonej grupy: wykluczenie dopiero po karencji.
	g, err := e.st.CreateGroup(context.Background(), store.AgentGroup{Name: "Testowe", Profile: "workstation"})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.AssignAgent(context.Background(), "agt-a", g.ID)
	fa.o.Policy.ExcludedAgents, fa.o.Policy.ExcludedGroups = []string{}, []int64{g.ID}
	fa.members = map[string]urd.Membership{"agt-a": {Group: g.ID, Since: e.clock.Add(-time.Hour)}}
	_, out, _ = admin.do("GET", "/api/v1/archive/policy", nil)
	un = out["unarchived"].([]any)
	if len(un) != 1 || un[0].(map[string]any)["reason"] != "group_pending" || un[0].(map[string]any)["effective_at"] == nil {
		t.Fatalf("przeniesienie do wyłączonej grupy w karencji: %v", out)
	}
	fa.members["agt-a"] = urd.Membership{Group: g.ID, Since: e.clock.Add(-48 * time.Hour)}
	if _, out, _ := admin.do("GET", "/api/v1/archive/policy", nil); out["unarchived"].([]any)[0].(map[string]any)["reason"] != "group" {
		t.Fatalf("po karencji: %v", out)
	}

	fa.o.Policy.Enabled = false
	if _, out, _ := admin.do("GET", "/api/v1/archive/policy", nil); len(out["unarchived"].([]any)) != 2 {
		t.Fatalf("wyłączone archiwum – wszyscy bez archiwizacji: %v", out)
	}
}
