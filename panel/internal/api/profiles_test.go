// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/store"
)

// memProfiles: profile w pamięci (testy).
type memProfiles struct {
	mu sync.Mutex
	st *memStore
	ps map[string]store.Profile
}

func (m *memProfiles) Profiles(context.Context) ([]store.Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.Profile{{ID: "admin", Builtin: true}, {ID: "analyst", Builtin: true}, {ID: "viewer", Builtin: true}}
	for _, p := range m.ps {
		out = append(out, p)
	}
	return out, nil
}
func (m *memProfiles) SaveProfile(_ context.Context, p store.Profile, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, x := range m.ps {
		if id != p.ID && x.Name == p.Name {
			return store.ErrConflict
		}
	}
	m.ps[p.ID] = p
	return nil
}
func (m *memProfiles) DeleteProfile(_ context.Context, id string) error {
	users, _ := m.st.ListUsers(context.Background())
	for _, u := range users {
		if u.Role == id {
			return store.ErrConflict
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ps[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.ps, id)
	return nil
}
func (m *memProfiles) ProfileUsers(context.Context) (map[string]int, error) {
	return map[string]int{}, nil
}

// Profil własny: dostęp tylko do wskazanych modułów; ochrona ostatniego
// administratora przy zmianie profilu; profil z kontami nie do usunięcia.
func TestCustomProfiles(t *testing.T) {
	e := &env{t: t, clock: time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	mp := &memProfiles{st: e.st, ps: map[string]store.Profile{}}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), UI: fstest.MapFS{"index.html": {Data: []byte("x")}}, Profiles: mp}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")

	if code, out, _ := a.do("PUT", "/api/v1/profiles/analyst", map[string]any{"name": "X", "permissions": map[string]string{}, "password": "bardzo-tajne-haslo-1"}); code != 409 {
		t.Fatalf("zmiana wbudowanego: %d %v", code, out)
	}
	if code, _, _ := a.do("PUT", "/api/v1/profiles/audytor", map[string]any{"name": "Audytor NIS2",
		"permissions": map[string]string{"archive": "admin"}, "password": "bardzo-tajne-haslo-1"}); code != 400 {
		t.Fatalf("nieznany poziom: %d", code)
	}
	if code, _, _ := a.do("PUT", "/api/v1/profiles/audytor", map[string]any{"name": "Audytor NIS2",
		"permissions": map[string]string{"archive": "export"}}); code != 403 {
		t.Fatalf("bez hasła: %d", code)
	}
	if code, out, _ := a.do("PUT", "/api/v1/profiles/audytor", map[string]any{"name": "Audytor NIS2",
		"permissions": map[string]string{"archive": "export"}, "password": "bardzo-tajne-haslo-1"}); code != 200 {
		t.Fatalf("zapis profilu: %d %v", code, out)
	}
	e.addUser("ewa", "audytor", "bardzo-tajne-haslo-2", false)
	c := e.client("10.0.0.2")
	code, out := c.login("ewa", "bardzo-tajne-haslo-2")
	if code != 200 || out["profile"].(map[string]any)["name"] != "Audytor NIS2" || out["permissions"].(map[string]any)["archive"] != "export" {
		t.Fatalf("logowanie z profilem: %d %v", code, out)
	}
	for path, want := range map[string]int{"/api/v1/archive": 200, "/api/v1/alerts": 403, "/api/v1/users": 403, "/api/v1/agents": 403} {
		if code, _, _ := c.do("GET", path, nil); code != want && !(want == 200 && code == 503) {
			t.Errorf("%s: %d, oczekiwane %d", path, code, want)
		}
	}
	// Profil administratora własny: odebranie zarządzania kontami ostatniemu adminowi – nie.
	a.do("PUT", "/api/v1/profiles/szef", map[string]any{"name": "Szef", "permissions": map[string]string{"users": "write"}, "password": "bardzo-tajne-haslo-1"})
	boss := e.addUser("szef", "szef", "bardzo-tajne-haslo-3", false)
	adminUser, _ := e.st.UserByUsername(context.Background(), "admin")
	if code, _, _ := a.do("PATCH", "/api/v1/users/"+itoa(adminUser.ID), map[string]string{"role": "viewer"}); code != 200 {
		t.Fatalf("admin → obserwator przy drugim administratorze: %d", code)
	}
	b := e.client("10.0.0.3")
	b.login("szef", "bardzo-tajne-haslo-3")
	if code, out, _ := b.do("PUT", "/api/v1/profiles/szef", map[string]any{"name": "Szef", "permissions": map[string]string{"users": "read"}, "password": "bardzo-tajne-haslo-3"}); code != 409 || out["error"] != "last_admin" {
		t.Fatalf("odebranie ostatniemu administratorowi: %d %v", code, out)
	}
	if code, out, _ := b.do("POST", "/api/v1/profiles/szef/delete", map[string]string{"password": "bardzo-tajne-haslo-3"}); code != 409 || out["error"] != "in_use" {
		t.Fatalf("usunięcie używanego: %d %v", code, out)
	}
	_ = boss
}
