package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

// memStore to baza w pamięci do testów (ta sama semantyka co store.PG).
type memStore struct {
	mu       sync.Mutex
	users    map[int64]store.User
	sessions map[string]store.Session
	agents   map[string]store.Agent
	audit    []store.AuditEntry
	nextID   int64
	now      func() time.Time
}

func newMemStore(now func() time.Time) *memStore {
	return &memStore{users: map[int64]store.User{}, sessions: map[string]store.Session{}, now: now}
}

func (m *memStore) Ping(context.Context) error { return nil }
func (m *memStore) CreateUser(_ context.Context, u store.User) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.users {
		if strings.EqualFold(x.Username, u.Username) {
			return store.User{}, store.ErrConflict
		}
	}
	m.nextID++
	u.ID, u.CreatedAt, u.UpdatedAt = m.nextID, m.now(), m.now()
	m.users[u.ID] = u
	return u, nil
}
func (m *memStore) UserByUsername(_ context.Context, name string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if strings.EqualFold(u.Username, name) {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}
func (m *memStore) UserByID(_ context.Context, id int64) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return u, store.ErrNotFound
	}
	return u, nil
}
func (m *memStore) ListUsers(context.Context) ([]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.User
	for _, u := range m.users {
		out = append(out, u)
	}
	return out, nil
}
func (m *memStore) UpdateUser(_ context.Context, id int64, p store.UserPatch) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return u, store.ErrNotFound
	}
	if p.DisplayName != nil {
		u.DisplayName = *p.DisplayName
	}
	if p.Role != nil {
		u.Role = *p.Role
	}
	if p.Disabled != nil {
		u.Disabled = *p.Disabled
	}
	m.users[id] = u
	return u, nil
}
func (m *memStore) SetPassword(_ context.Context, id int64, hash string, mustChange bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	u.PasswordHash, u.MustChangePassword, u.FailedLogins, u.LockedUntil = hash, mustChange, 0, nil
	m.users[id] = u
	return nil
}
func (m *memStore) RecordLoginFailure(_ context.Context, id int64, lockAfter int, lockFor time.Duration) (*time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	u.FailedLogins++
	if u.FailedLogins >= lockAfter {
		t := m.now().Add(lockFor)
		u.LockedUntil = &t
	}
	m.users[id] = u
	return u.LockedUntil, nil
}
func (m *memStore) RecordLoginSuccess(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	u.FailedLogins, u.LockedUntil = 0, nil
	m.users[id] = u
	return nil
}
func (m *memStore) CountActiveAdmins(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, u := range m.users {
		if u.Role == store.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n, nil
}
func (m *memStore) CreateSession(_ context.Context, s store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.LastSeenAt = s.CreatedAt
	m.sessions[s.ID] = s
	return nil
}
func (m *memStore) SessionWithUser(_ context.Context, id string, now time.Time) (store.Session, store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !s.ExpiresAt.After(now) {
		return s, store.User{}, store.ErrNotFound
	}
	return s, m.users[s.UserID], nil
}
func (m *memStore) TouchSession(_ context.Context, id string, seen, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	s.LastSeenAt, s.ExpiresAt = seen, expires
	m.sessions[id] = s
	return nil
}
func (m *memStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}
func (m *memStore) DeleteUserSessions(_ context.Context, userID int64, except string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.UserID == userID && id != except {
			delete(m.sessions, id)
		}
	}
	return nil
}
func (m *memStore) Audit(_ context.Context, e store.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return nil
}
func (m *memStore) ListAudit(context.Context, int, int64) ([]store.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.AuditEntry(nil), m.audit...), nil
}
func (m *memStore) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.audit {
		out = append(out, e.Action)
	}
	return out
}

// ---- pomocnicze ----

type env struct {
	t     *testing.T
	st    *memStore
	h     http.Handler
	clock time.Time
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, clock: time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler),
		UI: fstest.MapFS{"index.html": {Data: []byte("<html>APP</html>")}, "assets/app-1.js": {Data: []byte("js")}}}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	return e
}

func (e *env) addUser(name, role, password string, mustChange bool) store.User {
	h, err := auth.HashPassword(password)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.CreateUser(context.Background(), store.User{Username: name, Role: role, PasswordHash: h, MustChangePassword: mustChange})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// client to przeglądarka: ciasteczko sesji i token CSRF.
type client struct {
	e      *env
	ip     string
	cookie *http.Cookie
	csrf   string
}

func (e *env) client(ip string) *client { return &client{e: e, ip: ip} }

func (c *client) do(method, path string, body any) (int, map[string]any, *http.Response) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://panel"+path, rd)
	r.RemoteAddr = c.ip + ":50000"
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set(csrfHeader, c.csrf)
	}
	w := httptest.NewRecorder()
	c.e.h.ServeHTTP(w, r)
	res := w.Result()
	for _, ck := range res.Cookies() {
		if ck.Name == cookieName {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, res
}

func (c *client) login(user, pass string) (int, map[string]any) {
	code, out, _ := c.do("POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pass})
	if code == 200 {
		c.csrf = out["csrf_token"].(string)
	}
	return code, out
}

// ---- testy ----

func TestLoginSessionCookieAndCSRF(t *testing.T) {
	e := newEnv(t)
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	c := e.client("10.0.0.1")

	if code, out := c.login("ADMIN", "złe hasło"); code != 401 || out["error"] != "bad_credentials" {
		t.Fatalf("złe hasło: %d %v", code, out)
	}
	if code, out := c.login("nieznany", "cokolwiek"); code != 401 || out["message"] != badLogin {
		t.Fatalf("nieznany login musi wyglądać tak samo: %d %v", code, out)
	}
	code, out, res := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "Admin", "password": "bardzo-tajne-haslo-1"})
	if code != 200 {
		t.Fatalf("logowanie: %d", code)
	}
	c.csrf = out["csrf_token"].(string)
	ck := c.cookie
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Domain != "" {
		t.Fatalf("ciasteczko: %+v", ck)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("odpowiedź z tokenem nie może być cache'owana")
	}
	// Token z ciasteczka nie jest zapisany w bazie wprost.
	if _, ok := e.st.sessions[ck.Value]; ok {
		t.Fatal("baza przechowuje surowy token sesji")
	}

	// Zmiana stanu bez tokenu CSRF jest odrzucana.
	c2 := *c
	c2.csrf = ""
	if code, out, _ := c2.do("POST", "/api/v1/users", map[string]string{"username": "jan", "role": "viewer"}); code != 403 || out["error"] != "csrf" {
		t.Fatalf("bez CSRF: %d %v", code, out)
	}
	if code, out, _ := c.do("POST", "/api/v1/users", map[string]string{"username": "jan", "role": "viewer"}); code != 201 || out["temp_password"] == "" {
		t.Fatalf("z CSRF: %d %v", code, out)
	}

	// Wylogowanie unieważnia sesję po stronie serwera.
	old := c.cookie
	if code, _, _ := c.do("POST", "/api/v1/auth/logout", nil); code != 204 {
		t.Fatalf("wylogowanie: %d", code)
	}
	c.cookie = old
	if code, _, _ := c.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("sesja po wylogowaniu: %d", code)
	}
	want := []string{"login_failed", "login_failed", "login", "user_created", "logout"}
	if got := e.st.actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audyt: %v", got)
	}
}

func TestLockoutAndRateLimit(t *testing.T) {
	e := newEnv(t)
	e.addUser("jan", store.RoleViewer, "poprawne-haslo-jana", false)
	// Różne adresy – testujemy blokadę konta, nie limit na adres.
	for i := range 10 {
		if code, _ := e.client("10.1.0."+string(rune('a'+i))).login("jan", "złe"); code != 401 {
			t.Fatalf("próba %d: %d", i, code)
		}
	}
	if code, _ := e.client("10.2.0.1").login("jan", "poprawne-haslo-jana"); code != 401 {
		t.Fatal("zablokowane konto nie może się zalogować nawet poprawnym hasłem")
	}
	e.clock = e.clock.Add(16 * time.Minute)
	if code, _ := e.client("10.2.0.1").login("jan", "poprawne-haslo-jana"); code != 200 {
		t.Fatalf("po upływie blokady: %d", code)
	}

	// Limit prób z jednego adresu: 10 na minutę, potem 429.
	c := e.client("10.3.0.1")
	for range 10 {
		c.login("jan", "złe")
	}
	if code, out := c.login("jan", "złe"); code != 429 || out["error"] != "rate_limited" {
		t.Fatalf("limit na adres: %d %v", code, out)
	}
}

func TestMustChangePasswordFlow(t *testing.T) {
	e := newEnv(t)
	e.addUser("admin", store.RoleAdmin, "haslo-startowe-xyz", true)
	c := e.client("10.0.0.1")
	if code, out := c.login("admin", "haslo-startowe-xyz"); code != 200 || out["user"].(map[string]any)["must_change_password"] != true {
		t.Fatalf("logowanie: %d %v", code, out)
	}
	if code, out, _ := c.do("GET", "/api/v1/users", nil); code != 403 || out["error"] != "password_change_required" {
		t.Fatalf("przed zmianą hasła: %d %v", code, out)
	}
	// Druga sesja tego konta zostanie zamknięta po zmianie hasła.
	other := e.client("10.0.0.2")
	other.login("admin", "haslo-startowe-xyz")

	if code, out, _ := c.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "haslo-startowe-xyz", "new_password": "krotkie"}); code != 400 || out["error"] != "weak_password" {
		t.Fatalf("słabe hasło: %d %v", code, out)
	}
	if code, _, _ := c.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "złe", "new_password": "nowe-dlugie-haslo-123"}); code != 400 {
		t.Fatalf("złe obecne hasło: %d", code)
	}
	if code, _, _ := c.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "haslo-startowe-xyz", "new_password": "nowe-dlugie-haslo-123"}); code != 200 {
		t.Fatalf("zmiana hasła: %d", code)
	}
	if code, _, _ := c.do("GET", "/api/v1/users", nil); code != 200 {
		t.Fatalf("po zmianie hasła: %d", code)
	}
	if code, _, _ := other.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("inna sesja powinna wygasnąć po zmianie hasła: %d", code)
	}
}

func TestRolesAndLastAdmin(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser("admin", store.RoleAdmin, "haslo-admina-123", false)
	e.addUser("ola", store.RoleViewer, "haslo-oli-12345", false)
	viewer := e.client("10.0.0.2")
	viewer.login("ola", "haslo-oli-12345")
	if code, _, _ := viewer.do("GET", "/api/v1/users", nil); code != 403 {
		t.Fatalf("viewer → lista kont: %d", code)
	}
	if code, _, _ := viewer.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatalf("viewer → własna sesja: %d", code)
	}

	c := e.client("10.0.0.1")
	c.login("admin", "haslo-admina-123")
	id := "/api/v1/users/" + itoa(admin.ID)
	if code, out, _ := c.do("PATCH", id, map[string]any{"role": "viewer"}); code != 409 || out["error"] != "last_admin" {
		t.Fatalf("degradacja ostatniego admina: %d %v", code, out)
	}
	if code, out, _ := c.do("PATCH", id, map[string]any{"disabled": true}); code != 409 || out["error"] != "self" {
		t.Fatalf("wyłączenie siebie: %d %v", code, out)
	}
	// Awans Oli na admina, potem można zdegradować pierwszego.
	if code, _, _ := c.do("PATCH", "/api/v1/users/2", map[string]any{"role": "admin"}); code != 200 {
		t.Fatalf("awans: %d", code)
	}
	if code, _, _ := viewer.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("zmiana roli powinna zakończyć sesje konta: %d", code)
	}
	if code, _, _ := c.do("PATCH", id, map[string]any{"role": "analyst"}); code != 200 {
		t.Fatalf("degradacja przy dwóch adminach: %d", code)
	}
	if code, _, _ := c.do("PATCH", "/api/v1/users/99", map[string]any{"role": "analyst"}); code != 401 {
		// Własna rola zmieniona na analityka → sesja zamknięta.
		t.Fatalf("po utracie roli admina: %d", code)
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	e := newEnv(t)
	e.addUser("jan", store.RoleAnalyst, "haslo-jana-12345", false)
	c := e.client("10.0.0.1")
	c.login("jan", "haslo-jana-12345")
	for range 3 { // aktywność przesuwa limit bezczynności
		e.clock = e.clock.Add(50 * time.Minute)
		if code, _, _ := c.do("GET", "/api/v1/auth/session", nil); code != 200 {
			t.Fatalf("aktywna sesja: %d", code)
		}
	}
	e.clock = e.clock.Add(61 * time.Minute)
	if code, _, _ := c.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("po godzinie bezczynności: %d", code)
	}
	// Limit bezwzględny 8 h mimo aktywności.
	c.login("jan", "haslo-jana-12345")
	for range 9 {
		e.clock = e.clock.Add(55 * time.Minute)
		c.do("GET", "/api/v1/auth/session", nil)
	}
	if code, _, _ := c.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("po 8 h: %d", code)
	}
}

func TestUIAndHeaders(t *testing.T) {
	e := newEnv(t)
	c := e.client("10.0.0.1")
	for _, p := range []string{"/", "/agents", "/users/5"} {
		r := httptest.NewRequest("GET", "https://panel"+p, nil)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "APP") {
			t.Fatalf("%s: %d %q", p, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: brak nagłówków bezpieczeństwa", p)
		}
	}
	r := httptest.NewRequest("GET", "https://panel/assets/app-1.js", nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Body.String() != "js" || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("plik statyczny: %q %q", w.Body.String(), w.Header().Get("Cache-Control"))
	}
	if code, out, _ := c.do("GET", "/api/v1/nie-ma", nil); code != 404 || out["error"] != "not_found" {
		t.Fatalf("nieznane API: %d %v", code, out)
	}
	if code, _, _ := c.do("GET", "/api/v1/users", nil); code != 401 {
		t.Fatalf("bez sesji: %d", code)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
