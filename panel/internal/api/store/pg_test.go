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
	for _, tbl := range []string{"backup_files", "backup_requests", "backup_runs", "backup_runner", "backup_secrets", "backup_config", "agent_uninstall_tokens", "identity_shared_accounts", "identity_aliases", "identity_domains", "quarantine_outcomes", "quarantine_jobs", "syslog_decoder_versions", "syslog_decoders", "notify_log", "notify_channels", "agent_assignments", "agent_certs",
		"enrollment_tokens", "agent_groups", "agents", "audit_log", "sessions", "users", "schema_migrations"} {
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
}
