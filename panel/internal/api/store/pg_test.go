// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
)

// Test integracyjny na prawdziwym PostgreSQL. Uruchamiany tylko z adresem
// pustej bazy testowej w SIEM_TEST_PG_URL (np. na VM laboratoryjnej).
func TestPostgresStore(t *testing.T) {
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
	for _, tbl := range []string{"ai_analyses", "ai_pseudonyms", "api_token_requests", "api_tokens", "incident_reminders", "incident_reports", "incident_activity", "incident_alerts", "incidents", "panel_settings", "user_recovery_codes", "user_mfa", "backup_files", "backup_requests", "backup_runs", "backup_runner", "backup_secrets", "backup_config", "agent_uninstall_tokens", "identity_shared_accounts", "identity_aliases", "identity_domains", "quarantine_outcomes", "quarantine_jobs", "syslog_decoder_versions", "syslog_decoders", "notify_log", "notify_channels", "agent_assignments", "agent_certs",
		"enrollment_tokens", "agent_groups", "agents", "audit_log", "sessions", "users", "profiles", "schema_migrations"} {
		if _, err := db.pool.Exec(ctx, "DROP TABLE IF EXISTS "+tbl+" CASCADE"); err != nil {
			t.Fatal(err)
		}
	}

	applied, err := db.Migrate(ctx)
	if err != nil || len(applied) == 0 {
		t.Fatalf("migracje: %v %v", applied, err)
	}
	if again, err := db.Migrate(ctx); err != nil || len(again) != 0 {
		t.Fatalf("ponowne migracje powinny być puste: %v %v", again, err)
	}

	u, err := db.CreateUser(ctx, User{Username: "Admin", Role: RoleAdmin, PasswordHash: "h", MustChangePassword: true})
	if err != nil || u.ID == 0 || !u.MustChangePassword {
		t.Fatalf("tworzenie: %+v %v", u, err)
	}
	if _, err := db.CreateUser(ctx, User{Username: "admin", Role: RoleViewer, PasswordHash: "h"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("login bez rozróżniania wielkości liter powinien być unikalny: %v", err)
	}
	if _, err := db.CreateUser(ctx, User{Username: "zła nazwa!", Role: RoleViewer, PasswordHash: "h"}); err == nil {
		t.Fatal("baza powinna odrzucić niepoprawny login")
	}
	if _, err := db.CreateUser(ctx, User{Username: "x1", Role: "root", PasswordHash: "h"}); err == nil {
		t.Fatal("baza powinna odrzucić nieznaną rolę")
	}
	if got, err := db.UserByUsername(ctx, "ADMIN"); err != nil || got.ID != u.ID {
		t.Fatalf("wyszukanie: %+v %v", got, err)
	}
	if _, err := db.UserByID(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("brak konta: %v", err)
	}

	// Blokada po 3 porażkach na 15 minut.
	var until *time.Time
	for range 3 {
		if until, err = db.RecordLoginFailure(ctx, u.ID, 3, 15*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if until == nil || time.Until(*until) < 14*time.Minute || time.Until(*until) > 16*time.Minute {
		t.Fatalf("blokada: %v", until)
	}
	if err := db.SetPassword(ctx, u.ID, "h2", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.UserByID(ctx, u.ID); got.LockedUntil != nil || got.FailedLogins != 0 || got.MustChangePassword || got.PasswordHash != "h2" {
		t.Fatalf("po zmianie hasła: %+v", got)
	}

	viewer := "viewer"
	off := true
	v, _ := db.CreateUser(ctx, User{Username: "ola", Role: RoleAnalyst, PasswordHash: "h"})
	if got, err := db.UpdateUser(ctx, v.ID, UserPatch{Role: &viewer, Disabled: &off}); err != nil || got.Role != RoleViewer || !got.Disabled {
		t.Fatalf("aktualizacja: %+v %v", got, err)
	}
	if n, _ := db.CountActiveAdmins(ctx); n != 1 {
		t.Fatalf("aktywni admini: %d", n)
	}

	now := time.Now()
	for _, id := range []string{"s1", "s2"} {
		if err := db.CreateSession(ctx, Session{ID: id, UserID: u.ID, CSRF: "c", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if s, usr, err := db.SessionWithUser(ctx, "s1", now); err != nil || s.UserID != u.ID || usr.Username != "Admin" {
		t.Fatalf("sesja: %+v %+v %v", s, usr, err)
	}
	if _, _, err := db.SessionWithUser(ctx, "s1", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wygasła sesja: %v", err)
	}
	if err := db.DeleteUserSessions(ctx, u.ID, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.SessionWithUser(ctx, "s2", now); !errors.Is(err, ErrNotFound) {
		t.Fatal("s2 powinna zostać usunięta")
	}
	if n, err := db.DeleteExpiredSessions(ctx, now.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("sprzątanie: %d %v", n, err)
	}

	uid := u.ID
	for i, a := range []string{"login", "user_created", "logout"} {
		if err := db.Audit(ctx, AuditEntry{UserID: &uid, Username: "Admin", Action: a, Details: map[string]any{"n": i}}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := db.ListAudit(ctx, 2, 0)
	if err != nil || len(page) != 2 || page[0].Action != "logout" || page[0].Details["n"] != float64(2) {
		t.Fatalf("audyt: %+v %v", page, err)
	}
	older, _ := db.ListAudit(ctx, 2, page[1].ID)
	if len(older) != 1 || older[0].Action != "login" {
		t.Fatalf("starsza strona audytu: %+v", older)
	}

	testAgents(t, db)
	testEnrollment(t, db)
	testGroups(t, db)
}

func testAgents(t *testing.T, db *PG) {
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	exp := t0.Add(90 * 24 * time.Hour)
	a := Agent{ID: "agt-1", Hostname: "PC01", OS: "Windows 11", Version: "0.4.0", RemoteIP: "10.0.0.1",
		LastSeen: t0, CertNotAfter: &exp, CertSerial: "ab", Status: []byte(`{"counters":{"accepted":1}}`)}
	if err := db.UpsertAgents(ctx, []Agent{a, {ID: "agt-2", LastSeen: t0}}); err != nil {
		t.Fatal(err)
	}
	// Nowszy heartbeat aktualizuje, starszy (spóźniony) jest ignorowany.
	newer := a
	newer.LastSeen, newer.Version, newer.Status = t0.Add(time.Minute), "0.4.1", []byte(`{"counters":{"accepted":2}}`)
	older := a
	older.LastSeen, older.Version = t0.Add(-time.Minute), "0.3.0"
	if err := db.UpsertAgents(ctx, []Agent{newer}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAgents(ctx, []Agent{older}); err != nil {
		t.Fatal(err)
	}
	got, err := db.AgentByID(ctx, "agt-1")
	if err != nil || got.Version != "0.4.1" || !got.FirstSeen.Before(got.LastSeen.Add(time.Second)) ||
		got.CertNotAfter == nil || string(got.Status) != `{"counters": {"accepted": 2}}` {
		t.Fatalf("agent: %+v (%s) %v", got, got.Status, err)
	}
	list, err := db.ListAgents(ctx)
	if err != nil || len(list) != 2 || list[1].ID != "agt-2" || string(list[1].Status) != "{}" {
		t.Fatalf("lista: %+v %v", list, err)
	}
	if err := db.DeleteAgent(ctx, "agt-2"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteAgent(ctx, "agt-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ponowne usunięcie: %v", err)
	}
}

func testEnrollment(t *testing.T, db *PG) {
	ctx := context.Background()
	now := time.Now()
	tok, err := db.CreateEnrollToken(ctx, EnrollToken{Name: "Księgowość", TokenHash: "h1", Profile: "workstation", MaxUses: 2,
		ExpiresAt: now.Add(time.Hour), CreatedBy: "admin"})
	if err != nil || tok.ID == 0 || tok.Uses != 0 {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if _, err := db.CreateEnrollToken(ctx, EnrollToken{Name: "x", TokenHash: "h2", Profile: "root", ExpiresAt: now}); err == nil {
		t.Fatal("baza powinna odrzucić nieznany profil")
	}
	if got, err := db.EnrollTokenByHash(ctx, "h1", now); err != nil || got.ID != tok.ID {
		t.Fatalf("po skrócie: %+v %v", got, err)
	}
	for i := range 2 {
		if got, err := db.UseEnrollToken(ctx, "h1", now); err != nil || got.Uses != i+1 {
			t.Fatalf("użycie %d: %+v %v", i+1, got, err)
		}
	}
	if _, err := db.UseEnrollToken(ctx, "h1", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("po limicie: %v", err)
	}
	exp, _ := db.CreateEnrollToken(ctx, EnrollToken{Name: "stary", TokenHash: "h3", Profile: "server", ExpiresAt: now.Add(-time.Minute)})
	if _, err := db.UseEnrollToken(ctx, "h3", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wygasły: %v", err)
	}
	live, _ := db.CreateEnrollToken(ctx, EnrollToken{Name: "dc", TokenHash: "h4", Profile: "dc", ExpiresAt: now.Add(time.Hour)})
	if r, err := db.RevokeEnrollToken(ctx, live.ID); err != nil || r.RevokedAt == nil {
		t.Fatalf("unieważnienie tokenu: %+v %v", r, err)
	}
	if _, err := db.UseEnrollToken(ctx, "h4", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("unieważniony: %v", err)
	}
	if list, err := db.ListEnrollTokens(ctx); err != nil || len(list) != 3 || list[0].ID != live.ID || list[2].ID != tok.ID {
		t.Fatalf("lista: %d %v (%d)", len(list), err, exp.ID)
	}

	tid := tok.ID
	for _, c := range []AgentCert{
		{Serial: "aa01", AgentID: "agt-pc9", IssuedAt: now, NotAfter: now.Add(90 * 24 * time.Hour), TokenID: &tid, Hostname: "PC9"},
		{Serial: "aa02", AgentID: "agt-pc9", IssuedAt: now, NotAfter: now.Add(90 * 24 * time.Hour), RenewedFrom: "aa01"},
		{Serial: "aa03", AgentID: "agt-old", IssuedAt: now, NotAfter: now.Add(-time.Hour)},
	} {
		if err := db.RecordAgentCert(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if taken, err := db.AgentIDTaken(ctx, "agt-pc9"); err != nil || !taken {
		t.Fatalf("zajęty identyfikator: %v %v", taken, err)
	}
	if taken, _ := db.AgentIDTaken(ctx, "agt-wolny"); taken {
		t.Fatal("wolny identyfikator oznaczony jako zajęty")
	}
	serials, err := db.RevokeAgentCerts(ctx, "agt-pc9", "kradzież")
	if err != nil || len(serials) != 2 {
		t.Fatalf("unieważnienie certyfikatów: %v %v", serials, err)
	}
	if again, _ := db.RevokeAgentCerts(ctx, "agt-pc9", "ponownie"); len(again) != 0 {
		t.Fatalf("ponowne unieważnienie zwróciło %v", again)
	}
	// Lista agentów: bieżący certyfikat unieważniony – agent wycofany.
	if err := db.UpsertAgents(ctx, []Agent{{ID: "agt-pc9", Hostname: "PC9", LastSeen: now, CertSerial: "aa02", Status: []byte(`{}`)},
		{ID: "agt-pc8", Hostname: "PC8", LastSeen: now, CertSerial: "bb01", Status: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	if ags, err := db.ListAgents(ctx); err != nil || len(ags) < 2 || !ags[slices.IndexFunc(ags, func(a Agent) bool { return a.ID == "agt-pc9" })].CertRevoked ||
		ags[slices.IndexFunc(ags, func(a Agent) bool { return a.ID == "agt-pc8" })].CertRevoked {
		t.Fatalf("wycofanie w liście agentów: %+v %v", ags, err)
	}
	for _, id := range []string{"agt-pc9", "agt-pc8"} { // reszta testu liczy agentów w grupach
		if err := db.DeleteAgent(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	db.RevokeAgentCerts(ctx, "agt-old", "wygasły")
	if c, err := db.AgentCertBySerial(ctx, "aa02"); err != nil || c.RevokedAt == nil || c.RevokeReason != "kradzież" || c.RenewedFrom != "aa01" {
		t.Fatalf("certyfikat: %+v %v", c, err)
	}
	// Lista dla ingest: tylko unieważnione i jeszcze nie wygasłe.
	if rs, err := db.RevokedSerials(ctx, now); err != nil || len(rs) != 2 {
		t.Fatalf("unieważnione do rozesłania: %v %v", rs, err)
	}
	// Osierocone: ważny certyfikat agenta spoza listy (unieważnione i wygasłe – nie).
	if err := db.RecordAgentCert(ctx, AgentCert{Serial: "cc01", AgentID: "agt-usuniety", IssuedAt: now, NotAfter: now.Add(time.Hour), Hostname: "PCX"}); err != nil {
		t.Fatal(err)
	}
	if orph, err := db.OrphanAgentCerts(ctx, now); err != nil || len(orph) != 1 || orph[0].Serial != "cc01" {
		t.Fatalf("osierocone certyfikaty: %+v %v", orph, err)
	}
}

func testGroups(t *testing.T, db *PG) {
	ctx := context.Background()
	groups, err := db.ListGroups(ctx)
	if err != nil || len(groups) != 1 || !groups[0].IsDefault || groups[0].Profile != "workstation" {
		t.Fatalf("grupa domyślna z migracji: %+v %v", groups, err)
	}
	def := groups[0]
	five, eps := 5.0, 2000
	g, err := db.CreateGroup(ctx, AgentGroup{Name: "Serwery IIS", Profile: "server",
		Limits: contract.AgentLimits{CPUMaxPercent: &five, MaxEPS: &eps}})
	if err != nil || g.ID == 0 || *g.Limits.MaxEPS != 2000 {
		t.Fatalf("tworzenie: %+v %v", g, err)
	}
	if _, err := db.CreateGroup(ctx, AgentGroup{Name: "serwery iis", Profile: "dc"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("nazwa bez rozróżniania wielkości liter: %v", err)
	}
	g.Profile = "dc"
	if u, err := db.UpdateGroup(ctx, g); err != nil || u.Profile != "dc" {
		t.Fatalf("zmiana: %+v %v", u, err)
	}

	// agt-1 i agt-2 istnieją (heartbeat z testAgents); agt-1 trafia do grupy.
	if err := db.AssignAgent(ctx, "agt-1", g.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GroupForAgent(ctx, "agt-1"); err != nil || got.ID != g.ID {
		t.Fatalf("grupa agenta: %+v %v", got, err)
	}
	if got, err := db.GroupForAgent(ctx, "agt-nieznany"); err != nil || got.ID != def.ID {
		t.Fatalf("agent bez przypisania → domyślna: %+v %v", got, err)
	}
	groups, _ = db.ListGroups(ctx)
	counts := map[string]int{}
	for _, x := range groups {
		counts[x.Name] = x.Agents
	}
	if counts["Serwery IIS"] != 1 || counts["Domyślna"] != 0 {
		t.Fatalf("liczby agentów: %v", counts)
	}
	if err := db.DeleteGroup(ctx, g.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("usunięcie grupy z agentem: %v", err)
	}
	if err := db.DeleteGroup(ctx, def.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("usunięcie domyślnej: %v", err)
	}
	if err := db.AssignAgent(ctx, "agt-1", 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nieistniejąca grupa: %v", err)
	}
	if ids, err := db.AgentGroupIDs(ctx); err != nil || ids["agt-1"] != g.ID {
		t.Fatalf("przypisania: %v %v", ids, err)
	}

	// Token z grupą.
	tok, err := db.CreateEnrollToken(ctx, EnrollToken{Name: "IIS", TokenHash: "hg", Profile: "server",
		ExpiresAt: time.Now().Add(time.Hour), GroupID: &g.ID})
	if err != nil || tok.GroupID == nil || *tok.GroupID != g.ID {
		t.Fatalf("token z grupą: %+v %v", tok, err)
	}
	empty, _ := db.CreateGroup(ctx, AgentGroup{Name: "Pusta", Profile: "workstation"})
	if err := db.DeleteGroup(ctx, empty.ID); err != nil {
		t.Fatalf("usunięcie pustej: %v", err)
	}

	// Tokeny deinstalacji: jeden ważny naraz, użycie zgłoszone przez agenta.
	h1, h2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	t1, err := db.CreateUninstallToken(ctx, "agt-1", h1, "reinstalacja", "admin", time.Now().Add(time.Hour))
	if err != nil || t1.ID == 0 || t1.TokenID != "aaaaaaaaaaaa" {
		t.Fatalf("token deinstalacji: %+v %v", t1, err)
	}
	if _, err := db.CreateUninstallToken(ctx, "agt-1", h2, "drugi", "admin", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	act, err := db.ActiveUninstallTokens(ctx, "agt-1")
	if err != nil || len(act) != 1 || act[0].Hash != h2 {
		t.Fatalf("aktywne: %+v %v", act, err)
	}
	use := TokenUse{AgentID: "agt-1", TokenID: act[0].ID, Action: "uninstall_token", User: `AZUJO\jan`, At: time.Now()}
	foreign := TokenUse{AgentID: "agt-2", TokenID: act[0].ID, Action: "uninstall_token", At: time.Now()} // token innego agenta
	if applied, err := db.MarkUninstallTokensUsed(ctx, []TokenUse{use, foreign}); err != nil || len(applied) != 1 || applied[0] != use {
		t.Fatalf("użycie tokenu: %+v %v", applied, err)
	}
	// Kolejny heartbeat z tym samym zdarzeniem – nic nowego.
	if applied, err := db.MarkUninstallTokensUsed(ctx, []TokenUse{use}); err != nil || len(applied) != 0 {
		t.Fatalf("ponowne zgłoszenie: %+v %v", applied, err)
	}
	list, err := db.UninstallTokens(ctx, "agt-1", time.Now())
	if err != nil || len(list) != 2 || list[0].State != "used" || list[0].UsedBy != `AZUJO\jan` || list[1].State != "revoked" {
		t.Fatalf("lista tokenów: %+v %v", list, err)
	}
	if act, _ := db.ActiveUninstallTokens(ctx, "agt-1"); len(act) != 0 {
		t.Fatalf("użyty token nadal aktywny: %+v", act)
	}
	if ok, err := db.RevokeUninstallToken(ctx, "agt-1", list[0].ID, "admin"); ok || err != nil {
		t.Fatalf("unieważnienie użytego: %v %v", ok, err)
	}

	testMFA(ctx, t, db)
	testProfiles(ctx, t, db)
	testLDAPUsers(ctx, t, db)
	testIncidents(ctx, t, db)
}

// testIncidents: incydent z migawkami alertów, oś czasu, zmiana pól,
// zgłoszenie (szkic → wysłane, potem zamrożone), przypomnienia bez powtórzeń.
func testIncidents(ctx context.Context, t *testing.T, db *PG) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	al := IncidentAlert{AlertID: 11, RuleID: "r1", RuleTitle: "Brute force", Level: "high", HostName: "dc01", FirstSeen: now,
		LastSeen: now, AddedBy: "adam", AddedAt: now}
	x, err := db.CreateIncident(ctx, Incident{Title: "Atak", Severity: "high", CreatedBy: "adam", Assignee: "adam"}, []IncidentAlert{al}, now)
	if err != nil || x.ID == 0 || x.Status != "open" || x.AlertCount != 1 || x.Malicious != "unknown" {
		t.Fatalf("incydent: %+v %v", x, err)
	}
	al2 := al
	al2.AlertID = 12
	if err := db.AddIncidentAlerts(ctx, x.ID, []IncidentAlert{al, al2}, IncidentActivity{At: now, Username: "adam", Kind: "alerts_added"}); err != nil {
		t.Fatal(err)
	}
	if as, _ := db.IncidentAlerts(ctx, x.ID); len(as) != 2 {
		t.Fatalf("alerty: %+v", as)
	}
	if refs, _ := db.IncidentsForAlert(ctx, 12); len(refs) != 1 || refs[0].ID != x.ID {
		t.Fatalf("incydenty alertu: %+v", refs)
	}
	x.Significant, x.AwareAt = true, &now
	upd, err := db.UpdateIncident(ctx, x, []IncidentActivity{{At: now, Username: "adam", Kind: "field", Text: "significant"}}, now)
	if err != nil || upd.ClosedAt != nil || !upd.Significant {
		t.Fatalf("zmiana: %+v %v", upd, err)
	}
	if err := db.RemoveIncidentAlert(ctx, x.ID, 11, IncidentActivity{At: now, Username: "adam", Kind: "alert_removed"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIncidentReport(ctx, x.ID, "early_warning", "szkic", "adam", now); err != nil {
		t.Fatal(err)
	}
	if err := db.SubmitIncidentReport(ctx, x.ID, "early_warning", "wysłane", "CSIRT-1", "adam", now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIncidentReport(ctx, x.ID, "early_warning", "zmiana", "ewa", now); !errors.Is(err, ErrSubmitted) {
		t.Fatalf("zmiana wysłanego: %v", err)
	}
	if err := db.SubmitIncidentReport(ctx, x.ID, "early_warning", "x", "", "ewa", now, now); !errors.Is(err, ErrSubmitted) {
		t.Fatalf("ponowne wysłanie: %v", err)
	}
	reps, _ := db.IncidentReports(ctx, x.ID)
	if len(reps) != 1 || reps[0].Content != "wysłane" || reps[0].Reference != "CSIRT-1" || reps[0].SubmittedAt == nil {
		t.Fatalf("zgłoszenia: %+v", reps)
	}
	// Zamknięcie – ostateczne: żadnej zmiany ani notatki, zgłoszenia też nie.
	x.Status = "closed"
	if upd, err := db.UpdateIncident(ctx, x, []IncidentActivity{{At: now, Username: "adam", Kind: "field", Text: "status"}}, now); err != nil || upd.ClosedAt == nil {
		t.Fatalf("zamknięcie: %+v %v", upd, err)
	}
	x.Status = "open"
	if _, err := db.UpdateIncident(ctx, x, nil, now); !errors.Is(err, ErrClosed) {
		t.Fatalf("ponowne otwarcie: %v", err)
	}
	if err := db.AddIncidentActivity(ctx, x.ID, []IncidentActivity{{At: now, Username: "adam", Kind: "note", Text: "x"}}, now); !errors.Is(err, ErrClosed) {
		t.Fatalf("notatka w zamkniętym: %v", err)
	}
	if err := db.SaveIncidentReport(ctx, x.ID, "final", "x", "adam", now); !errors.Is(err, ErrClosed) {
		t.Fatalf("zgłoszenie w zamkniętym: %v", err)
	}
	if err := db.AddIncidentAlerts(ctx, x.ID, []IncidentAlert{al}, IncidentActivity{At: now, Username: "adam", Kind: "alerts_added"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("alert do zamkniętego: %v", err)
	}
	// Paczka dowodowa – także po zamknięciu.
	if err := db.AddIncidentEvidence(ctx, x.ID, IncidentActivity{At: now, Username: "adam", Kind: "evidence", Text: "eksport #1"}); err != nil {
		t.Fatalf("dowody w zamkniętym: %v", err)
	}
	if err := db.AddIncidentEvidence(ctx, 999999, IncidentActivity{At: now, Username: "adam", Kind: "evidence", Text: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dowody w nieistniejącym: %v", err)
	}
	act, _ := db.IncidentActivityLog(ctx, x.ID)
	kinds := []string{}
	for _, a := range act {
		kinds = append(kinds, a.Kind)
	}
	if strings.Join(kinds, ",") != "created,alerts_added,field,alert_removed,report_submitted,field,evidence" {
		t.Fatalf("oś czasu: %v", kinds)
	}
	if ok, _ := db.ReminderSent(ctx, x.ID, "notification", "soon", now); !ok {
		t.Fatal("pierwsze przypomnienie")
	}
	if ok, _ := db.ReminderSent(ctx, x.ID, "notification", "soon", now); ok {
		t.Fatal("powtórzone przypomnienie")
	}
	if list, _ := db.Incidents(ctx, "active"); len(list) != 0 {
		t.Fatalf("aktywne: %+v", list)
	}
	if list, _ := db.Incidents(ctx, "closed"); len(list) != 1 || list[0].AlertCount != 1 {
		t.Fatalf("zamknięte: %+v", list)
	}
}

// testLDAPUsers: konto domenowe zakładane i aktualizowane po SID; login
// zajęty przez konto lokalne – konflikt; wyłączenie w panelu zostaje.
func testLDAPUsers(ctx context.Context, t *testing.T, db *PG) {
	u, err := db.UpsertLDAPUser(ctx, User{Username: "jan.kowalski", DisplayName: "Jan", Role: RoleViewer,
		ExternalID: "S-1-5-21-1-1105", LDAPDN: "CN=Jan,DC=x"})
	if err != nil || u.Source != SourceLDAP || u.ExternalID != "S-1-5-21-1-1105" || u.MustChangePassword {
		t.Fatalf("konto domenowe: %+v %v", u, err)
	}
	disabled := true
	_, _ = db.UpdateUser(ctx, u.ID, UserPatch{Disabled: &disabled})
	u2, err := db.UpsertLDAPUser(ctx, User{Username: "jan.k", DisplayName: "Jan K", Role: RoleAnalyst,
		ExternalID: "S-1-5-21-1-1105", LDAPDN: "CN=Jan K,DC=x"})
	if err != nil || u2.ID != u.ID || u2.Username != "jan.k" || u2.Role != RoleAnalyst || !u2.Disabled || u2.LDAPDN != "CN=Jan K,DC=x" {
		t.Fatalf("aktualizacja po SID: %+v %v", u2, err)
	}
	if x, err := db.UserByExternalID(ctx, "S-1-5-21-1-1105"); err != nil || x.ID != u.ID {
		t.Fatalf("po SID: %+v %v", x, err)
	}
	if _, err := db.CreateUser(ctx, User{Username: "lokalny", Role: RoleViewer, PasswordHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertLDAPUser(ctx, User{Username: "lokalny", Role: RoleViewer, ExternalID: "S-1-5-21-1-1106"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("login zajęty przez konto lokalne: %v", err)
	}
	if l, _ := db.UserByUsername(ctx, "lokalny"); l.Source != SourceLocal {
		t.Fatalf("konto lokalne: %+v", l)
	}
}

// testProfiles: profile wbudowane z migracji, własny profil, klucz obcy kont.
func testProfiles(ctx context.Context, t *testing.T, db *PG) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	ps, err := db.Profiles(ctx)
	if err != nil || len(ps) != 3 || !ps[0].Builtin {
		t.Fatalf("profile wbudowane: %+v %v", ps, err)
	}
	if err := db.SaveProfile(ctx, Profile{ID: "admin", Name: "Zmiana"}, "x", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("zmiana wbudowanego: %v", err)
	}
	if err := db.SaveProfile(ctx, Profile{ID: "audytor", Name: "Audytor", Permissions: map[string]string{"archive": "export"}}, "adam", now); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveProfile(ctx, Profile{ID: "inny", Name: "audytor"}, "adam", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("ta sama nazwa: %v", err)
	}
	if _, err := db.CreateUser(ctx, User{Username: "bez-profilu", Role: "nie-ma", PasswordHash: "h"}); err == nil {
		t.Fatal("konto z nieistniejącym profilem")
	}
	u, err := db.CreateUser(ctx, User{Username: "audytor1", Role: "audytor", PasswordHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProfile(ctx, "audytor"); !errors.Is(err, ErrConflict) {
		t.Fatalf("usunięcie używanego: %v", err)
	}
	if n, _ := db.ProfileUsers(ctx); n["audytor"] != 1 {
		t.Fatalf("konta profilu: %v", n)
	}
	viewer := RoleViewer
	if _, err := db.UpdateUser(ctx, u.ID, UserPatch{Role: &viewer}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProfile(ctx, "audytor"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProfile(ctx, "viewer"); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("usunięcie wbudowanego: %v", err)
	}
}

// testMFA: drugi składnik konta, kody zapasowe, krok kodu, sesja, ustawienia.
func testMFA(ctx context.Context, t *testing.T, db *PG) {
	u, err := db.CreateUser(ctx, User{Username: "mfa-user", Role: RoleViewer, PasswordHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	if _, err := db.MFAState(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("konto bez MFA: %v", err)
	}
	if err := db.EnableMFA(ctx, u.ID, []byte{1, 2, 3}, 100, []string{"a", "b"}, now); err != nil {
		t.Fatal(err)
	}
	m, err := db.MFAState(ctx, u.ID)
	if err != nil || m.LastStep != 100 || m.RecoveryLeft != 2 || string(m.SecretEnc) != "\x01\x02\x03" {
		t.Fatalf("stan MFA: %+v %v", m, err)
	}
	if ok, _ := db.AdvanceMFAStep(ctx, u.ID, 100); ok {
		t.Fatal("ten sam krok drugi raz")
	}
	if ok, _ := db.AdvanceMFAStep(ctx, u.ID, 101); !ok {
		t.Fatal("późniejszy krok odrzucony")
	}
	if ok, left, err := db.UseRecoveryCode(ctx, u.ID, "a", now); !ok || left != 1 || err != nil {
		t.Fatalf("kod zapasowy: %v %d %v", ok, left, err)
	}
	if ok, _, _ := db.UseRecoveryCode(ctx, u.ID, "a", now); ok {
		t.Fatal("kod zapasowy drugi raz")
	}
	if err := db.ReplaceRecoveryCodes(ctx, u.ID, []string{"c", "d", "e"}); err != nil {
		t.Fatal(err)
	}
	if m, _ := db.MFAState(ctx, u.ID); m.RecoveryLeft != 3 {
		t.Fatalf("nowe kody: %+v", m)
	}
	if us, err := db.MFAEnabledUsers(ctx); err != nil || !us[u.ID].Equal(now) {
		t.Fatalf("konta z MFA: %v %v", us, err)
	}
	sess := Session{ID: "mfa-sess", UserID: u.ID, CSRF: "c", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkSessionMFA(ctx, "mfa-sess"); err != nil {
		t.Fatal(err)
	}
	if s, _, err := db.SessionWithUser(ctx, "mfa-sess", now); err != nil || !s.MFA {
		t.Fatalf("sesja z MFA: %+v %v", s, err)
	}
	if err := db.DisableMFA(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MFAState(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("po wyłączeniu: %v", err)
	}
	if _, err := db.Setting(ctx, "mfa_policy"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("brak ustawienia: %v", err)
	}
	_ = db.SetSetting(ctx, "mfa_policy", "admins", "adam", now)
	_ = db.SetSetting(ctx, "mfa_policy", "all", "ewa", now)
	if v, err := db.Setting(ctx, "mfa_policy"); v != "all" || err != nil {
		t.Fatalf("ustawienie: %q %v", v, err)
	}

	// Tokeny API: ważny po skrócie, unikalna nazwa wśród aktywnych,
	// wygaśnięcie i unieważnienie; profil z ważnym tokenem nie do usunięcia
	// (DeleteProfile liczy ważność według zegara bazy – czas bieżący).
	now = time.Now()
	if err := db.SaveProfile(ctx, Profile{ID: "integracje", Name: "Integracje", Permissions: map[string]string{"alerts": "read"}}, "adam", now); err != nil {
		t.Fatal(err)
	}
	tok, err := db.CreateAPIToken(ctx, APIToken{Name: "grafana", TokenHash: "hash-1", Prefix: "vardr_abc", Profile: "integracje",
		CreatedBy: "adam", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	if err != nil || tok.ID == 0 {
		t.Fatalf("token: %+v %v", tok, err)
	}
	if _, err := db.CreateAPIToken(ctx, APIToken{Name: "Grafana", TokenHash: "hash-2", Prefix: "vardr_def", Profile: "viewer",
		CreatedBy: "adam", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("druga aktywna nazwa: %v", err)
	}
	if got, err := db.APITokenByHash(ctx, "hash-1", now); err != nil || got.ID != tok.ID {
		t.Fatalf("po skrócie: %+v %v", got, err)
	}
	if _, err := db.APITokenByHash(ctx, "hash-1", now.Add(25*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wygasły: %v", err)
	}
	if err := db.TouchAPIToken(ctx, tok.ID, now, "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProfile(ctx, "integracje"); !errors.Is(err, ErrConflict) {
		t.Fatalf("profil z ważnym tokenem: %v", err)
	}
	if counts, err := db.ProfileTokens(ctx, now); err != nil || counts["integracje"] != 1 {
		t.Fatalf("tokeny profili: %v %v", counts, err)
	}
	if r, err := db.RevokeAPIToken(ctx, tok.ID, "ewa", now); err != nil || r.RevokedBy != "ewa" {
		t.Fatalf("unieważnienie: %+v %v", r, err)
	}
	if _, err := db.RevokeAPIToken(ctx, tok.ID, "ewa", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("drugie unieważnienie: %v", err)
	}
	if _, err := db.APITokenByHash(ctx, "hash-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unieważniony: %v", err)
	}
	list, err := db.ListAPITokens(ctx, now)
	if err != nil || len(list) != 1 || list[0].LastUsedIP != "10.0.0.5" || list[0].RevokedAt == nil {
		t.Fatalf("lista: %+v %v", list, err)
	}
	third, err := db.CreateAPIToken(ctx, APIToken{Name: "grafana", TokenHash: "hash-3", Prefix: "vardr_ghi", Profile: "integracje",
		CreatedBy: "adam", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("nazwa po unieważnieniu: %v", err)
	}
	// Historia zapytań tokenu: zapis paczką, odczyt od najnowszych ze
	// stronicowaniem, licznik i retencja.
	if err := db.RecordAPIRequests(ctx, []APIRequest{
		{TokenID: third.ID, At: now.Add(-48 * time.Hour), Method: "GET", Path: "/api/v1/alerts?status=open", Status: 200, DurationMS: 12, IP: "10.0.0.5"},
		{TokenID: third.ID, At: now, Method: "POST", Path: "/api/v1/groups", Status: 403, DurationMS: 1, IP: "10.0.0.5"},
	}); err != nil {
		t.Fatal(err)
	}
	reqs, err := db.APIRequests(ctx, third.ID, 1, 0)
	if err != nil || len(reqs) != 1 || reqs[0].Status != 403 {
		t.Fatalf("historia: %+v %v", reqs, err)
	}
	if older, err := db.APIRequests(ctx, third.ID, 10, reqs[0].ID); err != nil || len(older) != 1 || older[0].Path != "/api/v1/alerts?status=open" {
		t.Fatalf("starsze: %+v %v", older, err)
	}
	if counts, err := db.APIRequestCounts(ctx, now.Add(-24*time.Hour)); err != nil || counts[third.ID] != 1 {
		t.Fatalf("licznik 24 h: %v %v", counts, err)
	}
	if n, err := db.DeleteOldAPIRequests(ctx, now.Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("retencja: %d %v", n, err)
	}
	// Token AI: rodzaj, historia zapytań tokenów AI i pseudonimy maskowania.
	aiTok, err := db.CreateAPIToken(ctx, APIToken{Name: "claude", TokenHash: "hash-ai", Prefix: "vardr_ai", Profile: "viewer",
		CreatedBy: "adam", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Kind: TokenAI})
	if err != nil || aiTok.Kind != TokenAI || third.Kind != TokenIntegration {
		t.Fatalf("rodzaj tokenu: %+v %+v %v", aiTok, third, err)
	}
	if err := db.RecordAPIRequests(ctx, []APIRequest{{TokenID: aiTok.ID, At: now, Method: "GET", Path: "/api/v1/alerts", Status: 200}}); err != nil {
		t.Fatal(err)
	}
	if ai, err := db.APIRequestsByKind(ctx, TokenAI, 10, 0); err != nil || len(ai) != 1 || ai[0].TokenName != "claude" {
		t.Fatalf("historia AI: %+v %v", ai, err)
	}
	if err := db.SavePseudonyms(ctx, []Pseudonym{{Pseudonym: "USER-0000ABCD", Kind: "USER", Value: `AZUJO\jan`}}, now); err != nil {
		t.Fatal(err)
	}
	if err := db.SavePseudonyms(ctx, []Pseudonym{{Pseudonym: "USER-0000ABCD", Kind: "USER", Value: `AZUJO\jan`}}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ps, err := db.PseudonymOf(ctx, "USER-0000ABCD"); err != nil || ps.Value != `AZUJO\jan` || !ps.LastSeen.After(ps.FirstSeen) {
		t.Fatalf("pseudonim: %+v %v", ps, err)
	}
	if _, err := db.PseudonymOf(ctx, "USER-FFFFFFFF"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nieznany pseudonim: %v", err)
	}
	if _, err := db.RevokeAPIToken(ctx, aiTok.ID, "adam", now); err != nil {
		t.Fatal(err)
	}

	// Sprzątanie: inne testy (profile) zakładają tylko profile wbudowane.
	if _, err := db.RevokeAPIToken(ctx, third.ID, "adam", now); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteProfile(ctx, "integracje"); err != nil {
		t.Fatalf("profil bez ważnych tokenów: %v", err)
	}

	// Kanał Power Automate / Teams z podpisem: sekret zapisany przy
	// utworzeniu, zostaje przy zmianie kanału, wyłączany i zmieniany osobno.
	ch, err := db.CreateChannel(ctx, Channel{Name: "Teams SOC", Kind: "teams", URL: "https://x.logic.azure.com/workflows/a",
		Events: []string{"alert"}, Enabled: true, CreatedBy: "adam", SigningSecret: "vardrsig_1"})
	if err != nil || !ch.Signed || ch.SigningSecret != "vardrsig_1" {
		t.Fatalf("kanał Teams: %+v %v", ch, err)
	}
	if _, err := db.CreateChannel(ctx, Channel{Name: "zły", Kind: "slack", URL: "https://x", CreatedBy: "adam"}); err == nil {
		t.Fatal("baza powinna odrzucić nieznany rodzaj kanału")
	}
	if upd, err := db.UpdateChannel(ctx, Channel{ID: ch.ID, Name: "Teams", Events: []string{"alert", "incident"}, Enabled: true}); err != nil || upd.SigningSecret != "vardrsig_1" {
		t.Fatalf("zmiana kanału a sekret: %+v %v", upd, err)
	}
	if upd, err := db.SetChannelSecret(ctx, ch.ID, ""); err != nil || upd.Signed {
		t.Fatalf("wyłączenie podpisu: %+v %v", upd, err)
	}
	if err := db.DeleteChannel(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
}
