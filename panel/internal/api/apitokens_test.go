// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/store"
)

type memAPITokens struct {
	mu     sync.Mutex
	list   []store.APIToken
	nextID int64
	reqs   []store.APIRequest
}

func (m *memAPITokens) RecordAPIRequests(_ context.Context, reqs []store.APIRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range reqs {
		r.ID = int64(len(m.reqs) + 1)
		m.reqs = append(m.reqs, r)
	}
	return nil
}
func (m *memAPITokens) APIRequests(_ context.Context, tokenID int64, limit int, beforeID int64) ([]store.APIRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.APIRequest{}
	for i := len(m.reqs) - 1; i >= 0 && len(out) < limit; i-- {
		if r := m.reqs[i]; r.TokenID == tokenID && (beforeID == 0 || r.ID < beforeID) {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memAPITokens) APIRequestCounts(_ context.Context, since time.Time) (map[int64]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]int{}
	for _, r := range m.reqs {
		if r.At.After(since) {
			out[r.TokenID]++
		}
	}
	return out, nil
}

func (m *memAPITokens) CreateAPIToken(_ context.Context, t store.APIToken) (store.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.list {
		if x.RevokedAt == nil && strings.EqualFold(x.Name, t.Name) {
			return t, store.ErrConflict
		}
	}
	m.nextID++
	t.ID = m.nextID
	m.list = append(m.list, t)
	return t, nil
}
func (m *memAPITokens) ListAPITokens(context.Context, time.Time) ([]store.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.APIToken(nil), m.list...), nil
}
func (m *memAPITokens) APITokenByHash(_ context.Context, hash string, now time.Time) (store.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.list {
		if t.TokenHash == hash && t.RevokedAt == nil && t.ExpiresAt.After(now) {
			return t, nil
		}
	}
	return store.APIToken{}, store.ErrNotFound
}
func (m *memAPITokens) TouchAPIToken(_ context.Context, id int64, at time.Time, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.list {
		if m.list[i].ID == id {
			m.list[i].LastUsedAt, m.list[i].LastUsedIP = &at, ip
		}
	}
	return nil
}
func (m *memAPITokens) RevokeAPIToken(_ context.Context, id int64, by string, now time.Time) (store.APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.list {
		if m.list[i].ID == id && m.list[i].RevokedAt == nil {
			m.list[i].RevokedAt, m.list[i].RevokedBy = &now, by
			return m.list[i], nil
		}
	}
	return store.APIToken{}, store.ErrNotFound
}

func newTokenEnv(t *testing.T, rate int) (*env, *memAPITokens) {
	e, mt, _ := newTokenEnvSrv(t, rate)
	return e, mt
}

func newTokenEnvSrv(t *testing.T, rate int) (*env, *memAPITokens, *Server) {
	e := &env{t: t, clock: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	mt := &memAPITokens{}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), UI: fstest.MapFS{"index.html": {Data: []byte("x")}},
		APITokens: mt, TokenRatePerMin: rate}
	srv.now = func() time.Time { return e.clock }
	e.h = srv.Handler()
	return e, mt, srv
}

// bearer wysyła żądanie programu z tokenem (bez ciasteczka i CSRF).
func (e *env) bearer(token, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, "https://panel"+path, rd)
	r.RemoteAddr = "10.9.9.9:40000"
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func createToken(t *testing.T, a *client, name, profile string, days int) string {
	t.Helper()
	code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": name, "profile": profile, "days": days,
		"password": "bardzo-tajne-haslo-1"})
	if code != 201 {
		t.Fatalf("utworzenie tokenu %s: %d %v", name, code, out)
	}
	return out["secret"].(string)
}

// Token z profilem obserwatora: odczyt w granicach profilu, odmowa zmian
// z wpisem w audycie, trasy sesji niedostępne, unieważnienie i wygaśnięcie.
func TestAPITokenAccess(t *testing.T) {
	e, mt := newTokenEnv(t, 0)
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")

	if code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "grafana", "profile": "viewer"}); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("utworzenie bez hasła: %d %v", code, out)
	}
	if code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "grafana", "profile": "viewer", "days": 400,
		"password": "bardzo-tajne-haslo-1"}); code != 400 || out["error"] != "bad_token_days" {
		t.Fatalf("ważność ponad rok: %d %v", code, out)
	}
	secret := createToken(t, a, "grafana", "viewer", 30)
	if !strings.HasPrefix(secret, "vardr_") || len(secret) < 40 {
		t.Fatalf("token: %q", secret)
	}
	if mt.list[0].TokenHash == secret || !strings.HasPrefix(secret, mt.list[0].Prefix) {
		t.Fatal("w bazie ma być skrót i początek tokenu, nie token")
	}
	if code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "Grafana", "profile": "viewer",
		"password": "bardzo-tajne-haslo-1"}); code != 409 {
		t.Fatalf("druga aktywna o tej nazwie: %d %v", code, out)
	}

	if code, out := e.bearer(secret, "GET", "/api/v1/agents", nil); code != 200 {
		t.Fatalf("odczyt agentów tokenem: %d %v", code, out)
	}
	if code, out := e.bearer(secret, "GET", "/api/v1/api-tokens/self", nil); code != 200 || out["actor"] != "api:grafana" || out["profile"] != "viewer" {
		t.Fatalf("self: %d %v", code, out)
	}
	if mt.list[0].LastUsedAt == nil || mt.list[0].LastUsedIP != "10.9.9.9" {
		t.Fatal("brak zapisu ostatniego użycia")
	}
	// Zmiana poza profilem: 403 bez CSRF-owego zamieszania i wpis w audycie.
	if code, out := e.bearer(secret, "POST", "/api/v1/groups", map[string]any{"name": "X", "profile": "server"}); code != 403 || out["error"] != "forbidden" {
		t.Fatalf("zmiana tokenem obserwatora: %d %v", code, out)
	}
	audit, _ := e.st.ListAudit(context.Background(), 0, 0)
	last := audit[len(audit)-1]
	if last.Action != "api_token_denied" || last.Username != "api:grafana" || last.UserID != nil || last.Details["path"] != "/api/v1/groups" {
		t.Fatalf("wpis audytu odmowy: %+v", last)
	}
	for _, p := range []string{"/api/v1/auth/session", "/api/v1/account/mfa"} {
		if code, out := e.bearer(secret, "GET", p, nil); code != 403 || out["error"] != "token_not_allowed" {
			t.Errorf("%s tokenem: %d %v", p, code, out)
		}
	}
	if code, _ := e.bearer(secret, "GET", "/api/v1/permissions", nil); code != 200 {
		t.Errorf("lista uprawnień tokenem: %d", code)
	}
	if code, out := e.bearer("vardr_zly", "GET", "/api/v1/agents", nil); code != 401 || out["error"] != "invalid_token" {
		t.Fatalf("zły token: %d %v", code, out)
	}
	if code, _ := e.bearer("abc", "GET", "/api/v1/agents", nil); code != 401 {
		t.Fatalf("token bez prefiksu: %d", code)
	}

	// Wygaśnięcie.
	e.clock = e.clock.Add(31 * 24 * time.Hour)
	if code, _ := e.bearer(secret, "GET", "/api/v1/agents", nil); code != 401 {
		t.Fatalf("wygasły token: %d", code)
	}
	a.login("admin", "bardzo-tajne-haslo-1")
	second := createToken(t, a, "skrypt", "viewer", 0) // 0 – domyślne 90 dni
	if code, _ := e.bearer(second, "GET", "/api/v1/agents", nil); code != 200 {
		t.Fatalf("drugi token: %d", code)
	}
	if code, out, _ := a.do("POST", "/api/v1/api-tokens/2/revoke", nil); code != 200 {
		t.Fatalf("unieważnienie: %d %v", code, out)
	}
	if code, _ := e.bearer(second, "GET", "/api/v1/agents", nil); code != 401 {
		t.Fatalf("unieważniony token: %d", code)
	}
}

// Token z profilem administratora: zmiany bez CSRF zapisane w audycie jako
// api:<nazwa>; bez zarządzania kontami, profilami, tokenami i bez operacji
// chronionych hasłem.
func TestAPITokenAdminProfile(t *testing.T) {
	e, _ := newTokenEnv(t, 0)
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	secret := createToken(t, a, "soar", "admin", 30)

	if code, out := e.bearer(secret, "POST", "/api/v1/groups", map[string]any{"name": "Serwery", "profile": "server"}); code != 201 {
		t.Fatalf("zmiana tokenem administratora: %d %v", code, out)
	}
	audit, _ := e.st.ListAudit(context.Background(), 0, 0)
	last := audit[len(audit)-1]
	if last.Action != "group_created" || last.Username != "api:soar" || last.UserID != nil || last.Details["api_token_id"] != int64(1) {
		t.Fatalf("audyt zmiany tokenem: %+v", last)
	}
	if code, _ := e.bearer(secret, "GET", "/api/v1/users", nil); code != 200 {
		t.Fatalf("odczyt kont: %d", code)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/users"}, {"POST", "/api/v1/api-tokens"}, {"PUT", "/api/v1/profiles/x"},
	} {
		if code, out := e.bearer(secret, c.method, c.path, map[string]any{}); code != 403 {
			t.Errorf("%s %s tokenem: %d %v", c.method, c.path, code, out)
		}
	}
}

func TestAPITokenRateLimit(t *testing.T) {
	e, _ := newTokenEnv(t, 60) // 60/min, zapas 10
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	secret := createToken(t, a, "szybki", "viewer", 30)
	limited := 0
	for range 20 {
		if code, _ := e.bearer(secret, "GET", "/api/v1/agents", nil); code == 429 {
			limited++
		}
	}
	if limited == 0 || limited > 11 {
		t.Fatalf("odmowy 429: %d z 20", limited)
	}
}

// Opis OpenAPI zawiera każdą trasę z uprawnieniem i dostępnością dla tokenów.
func TestOpenAPI(t *testing.T) {
	e, _ := newTokenEnv(t, 0)
	code, doc, _ := e.client("10.0.0.1").do("GET", "/api/v1/openapi.json", nil)
	if code != 200 || doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi: %d", code)
	}
	paths := doc["paths"].(map[string]any)
	srv := &Server{}
	for _, rt := range srv.routes() {
		method, path, _ := strings.Cut(rt.pattern, " ")
		op, ok := paths[path].(map[string]any)[strings.ToLower(method)].(map[string]any)
		if !ok {
			t.Errorf("brak %s w opisie", rt.pattern)
			continue
		}
		if op["operationId"] == "" || op["summary"] == "" {
			t.Errorf("%s: bez nazwy", rt.pattern)
		}
	}
	alerts := paths["/api/v1/alerts"].(map[string]any)["get"].(map[string]any)
	if alerts["x-vardr-permission"] != "alerts:read" || alerts["x-vardr-token"] != true || alerts["summary"] != "List alerts" {
		t.Errorf("alerty: %v", alerts)
	}
	if mfa := paths["/api/v1/account/mfa"].(map[string]any)["get"].(map[string]any); mfa["x-vardr-token"] != false {
		t.Errorf("MFA konta dostępne dla tokenu: %v", mfa)
	}
	if s := summaryOf("listAPITokens"); s != "List API tokens" {
		t.Errorf("summaryOf: %q", s)
	}
}

// Historia zapytań: każde zapytanie tokenu (także odmowa) z metodą,
// ścieżką z parametrami i wynikiem; licznik z 24 h na liście tokenów.
func TestAPITokenRequestHistory(t *testing.T) {
	e, mt, srv := newTokenEnvSrv(t, 0)
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	secret := createToken(t, a, "raporty", "viewer", 30)

	e.bearer(secret, "GET", "/api/v1/agents?x=1", nil)
	e.bearer(secret, "POST", "/api/v1/groups", map[string]any{"name": "X", "profile": "server"})
	srv.flushTokenLog(context.Background())
	if len(mt.reqs) != 2 {
		t.Fatalf("zapisane zapytania: %+v", mt.reqs)
	}
	code, out, _ := a.do("GET", "/api/v1/api-tokens/1/requests", nil)
	reqs, _ := out["requests"].([]any)
	if code != 200 || len(reqs) != 2 {
		t.Fatalf("historia: %d %v", code, out)
	}
	newest, oldest := reqs[0].(map[string]any), reqs[1].(map[string]any)
	if newest["method"] != "POST" || newest["status"] != float64(403) || oldest["path"] != "/api/v1/agents?x=1" ||
		oldest["status"] != float64(200) || oldest["ip"] != "10.9.9.9" {
		t.Fatalf("wpisy: %v", reqs)
	}
	code, out, _ = a.do("GET", "/api/v1/api-tokens", nil)
	if counts := out["requests_24h"].(map[string]any); code != 200 || counts["1"] != float64(2) {
		t.Fatalf("licznik 24 h: %d %v", code, out)
	}
	// Zapytania sesją panelu nie trafiają do historii tokenów.
	if len(mt.reqs) != 2 {
		t.Fatalf("zapytania panelu w historii: %d", len(mt.reqs))
	}
}
