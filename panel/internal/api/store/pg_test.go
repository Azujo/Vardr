package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
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
	for _, tbl := range []string{"audit_log", "sessions", "users", "schema_migrations"} {
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
}
