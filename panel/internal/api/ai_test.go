// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"siem/panel/internal/api/store"
)

type memSettings struct {
	mu sync.Mutex
	kv map[string]string
}

func (m *memSettings) Setting(_ context.Context, k string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.kv[k]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}
func (m *memSettings) SetSetting(_ context.Context, k, v, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv[k] = v
	return nil
}

type memAI struct {
	mu sync.Mutex
	ps map[string]store.Pseudonym
	an []store.AlertAnalysis
}

func (m *memAI) APIRequestsByKind(context.Context, string, int, int64) ([]store.KindRequest, error) {
	return []store.KindRequest{}, nil
}
func (m *memAI) SavePseudonyms(_ context.Context, ps []store.Pseudonym, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range ps {
		m.ps[p.Pseudonym] = p
	}
	return nil
}
func (m *memAI) PseudonymOf(_ context.Context, p string) (store.Pseudonym, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.ps[p]
	if !ok {
		return v, store.ErrNotFound
	}
	return v, nil
}

func newAIEnv(t *testing.T) (*env, *memAI) { return newAIEnvWith(t, nil) }

// newAIEnvWith: środowisko AI z dodatkowymi zależnościami serwera (setup).
func newAIEnvWith(t *testing.T, setup func(*Server)) (*env, *memAI) {
	e := &env{t: t, clock: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)}
	e.st = newMemStore(func() time.Time { return e.clock })
	ai := &memAI{ps: map[string]store.Pseudonym{}}
	srv := &Server{Store: e.st, Log: slog.New(slog.DiscardHandler), UI: fstest.MapFS{"index.html": {Data: []byte("x")}},
		APITokens: &memAPITokens{}, Settings: &memSettings{kv: map[string]string{}}, AI: ai}
	srv.now = func() time.Time { return e.clock }
	if setup != nil {
		setup(srv)
	}
	e.h = srv.Handler()
	e.addUser("admin", store.RoleAdmin, "bardzo-tajne-haslo-1", false)
	e.st.agents = map[string]store.Agent{"agt-1": {ID: "agt-1", Hostname: "PC-JANA", RemoteIP: "10.1.2.3"}}
	return e, ai
}

func setPolicy(t *testing.T, a *client, pol map[string]any, ack bool) (int, map[string]any) {
	t.Helper()
	code, out, _ := a.do("PUT", "/api/v1/ai/policy", map[string]any{"policy": pol, "acknowledge": ack, "password": "bardzo-tajne-haslo-1"})
	return code, out
}

// Token AI: bez włączonej polityki – nic; włączenie wymaga potwierdzenia
// ostrzeżeń; tylko trasy włączonych narzędzi; zmiany nigdy.
func TestAIPolicyGate(t *testing.T) {
	e, _ := newAIEnv(t)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	if code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "claude", "profile": "admin", "kind": "ai",
		"password": "bardzo-tajne-haslo-1"}); code != 400 || out["error"] != "ai_ack_required" {
		t.Fatalf("token AI bez potwierdzenia: %d %v", code, out)
	}
	code, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "claude", "profile": "admin", "kind": "ai",
		"acknowledge": true, "password": "bardzo-tajne-haslo-1"})
	if code != 201 {
		t.Fatalf("token AI: %d %v", code, out)
	}
	ai := out["secret"].(string)
	integ := createToken(t, a, "skrypt", "admin", 30)

	if code, out := e.bearer(ai, "GET", "/api/v1/agents", nil); code != 403 || out["error"] != "ai_disabled" {
		t.Fatalf("polityka wyłączona: %d %v", code, out)
	}
	if code, _ := e.bearer(integ, "GET", "/api/v1/agents", nil); code != 200 {
		t.Fatalf("token integracji nie podlega polityce AI: %d", code)
	}
	pol := map[string]any{"enabled": true, "tools": map[string]bool{"system": true, "alerts": false}}
	if code, out := setPolicy(t, a, pol, false); code != 400 || out["error"] != "ai_ack_required" {
		t.Fatalf("włączenie bez potwierdzenia: %d %v", code, out)
	}
	if code, out := setPolicy(t, a, pol, true); code != 200 {
		t.Fatalf("włączenie: %d %v", code, out)
	}
	if code, _ := e.bearer(ai, "GET", "/api/v1/agents", nil); code != 200 {
		t.Fatalf("narzędzie system: %d", code)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/users"},                         // poza narzędziami AI (profil pozwala)
		{"GET", "/api/v1/audit"},                         // jw.
		{"POST", "/api/v1/groups"},                       // zmiana – nigdy
		{"GET", "/api/v1/agents/agt-1/uninstall-tokens"}, // poza listą
	} {
		if code, out := e.bearer(ai, c.method, c.path, map[string]any{}); code != 403 || out["error"] != "ai_not_allowed" {
			t.Errorf("%s %s tokenem AI: %d %v", c.method, c.path, code, out)
		}
	}
	if code, out := e.bearer(ai, "GET", "/api/v1/ai/policy", nil); code != 200 || out["policy"].(map[string]any)["enabled"] != true {
		t.Fatalf("polityka dla vardr-mcp: %d %v", code, out)
	}
	if code, out := e.bearer(ai, "GET", "/api/v1/api-tokens/self", nil); code != 200 || out["kind"] != "ai" {
		t.Fatalf("self: %d %v", code, out)
	}
	audit, _ := e.st.ListAudit(context.Background(), 0, 0)
	var denied, policy int
	for _, en := range audit {
		switch en.Action {
		case "api_token_denied":
			denied++
		case "ai_policy_changed":
			policy++
			if en.Details["acknowledged"] != true {
				t.Errorf("potwierdzenie ostrzeżeń w audycie: %v", en.Details)
			}
		}
	}
	if denied == 0 || policy != 1 {
		t.Fatalf("audyt: odmowy %d, zmiany polityki %d", denied, policy)
	}
}

// Maskowanie: pola i tekst wolny na stałe pseudonimy, zapis do odkrycia
// w panelu (z powodem i audytem).
func TestAIMasking(t *testing.T) {
	e, mem := newAIEnv(t)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	_, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "claude", "profile": "admin", "kind": "ai",
		"acknowledge": true, "password": "bardzo-tajne-haslo-1"})
	ai := out["secret"].(string)
	setPolicy(t, a, map[string]any{"enabled": true, "tools": map[string]bool{"system": true},
		"mask": map[string]bool{"users": true, "hosts": true, "ips": true, "emails": true}}, true)

	code, out := e.bearer(ai, "GET", "/api/v1/agents", nil)
	raw, _ := json.Marshal(out)
	if code != 200 || strings.Contains(string(raw), "PC-JANA") || strings.Contains(string(raw), "10.1.2.3") {
		t.Fatalf("maskowanie: %d %s", code, raw)
	}
	var host string
	for p, v := range mem.ps {
		if v.Value == "PC-JANA" {
			host = p
		}
	}
	if !strings.HasPrefix(host, "HOST-") || !strings.Contains(string(raw), host) {
		t.Fatalf("pseudonim komputera %q w %s", host, raw)
	}
	// Ten sam komputer – ten sam pseudonim w kolejnej odpowiedzi.
	_, out2 := e.bearer(ai, "GET", "/api/v1/agents", nil)
	if raw2, _ := json.Marshal(out2); !strings.Contains(string(raw2), host) {
		t.Fatal("pseudonim niestały")
	}
	if code, _, _ := a.do("POST", "/api/v1/ai/reveal", map[string]any{"pseudonym": host}); code != 400 {
		t.Fatalf("odkrycie bez powodu: %d", code)
	}
	code, out, _ = a.do("POST", "/api/v1/ai/reveal", map[string]any{"pseudonym": strings.ToLower(host), "reason": "alert 42"})
	if code != 200 || out["pseudonym"].(map[string]any)["value"] != "PC-JANA" {
		t.Fatalf("odkrycie: %d %v", code, out)
	}
	if !strings.Contains(strings.Join(e.st.actions(), ","), "ai_pseudonym_revealed") {
		t.Fatal("odkrycie bez wpisu w audycie")
	}
	// Token AI nie odkrywa pseudonimów (trasa poza narzędziami AI).
	if code, _ := e.bearer(ai, "POST", "/api/v1/ai/reveal", map[string]any{"pseudonym": host, "reason": "x"}); code != 403 {
		t.Fatalf("odkrycie tokenem AI: %d", code)
	}
}

func TestMaskJSONFreeText(t *testing.T) {
	body := []byte(`{"alerts":[{"user_name":"AZUJO\\jan.kowalski","host_name":"pc01.azujo.local","source_ip":"10.0.5.23",
		"summary":"Nieudane logowanie jan.kowalski z 10.0.5.23 na pc01.azujo.local, kontakt jan@azujo.pl","hits":3,
		"group_fields":{"user.name":"AZUJO\\jan.kowalski"}}],"total":1}`)
	out, ps, err := maskJSON(body, []byte("klucz-testowy-123456"), AIMask{Users: true, Hosts: true, IPs: true, Emails: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"jan.kowalski", "10.0.5.23", "pc01", "jan@azujo.pl"} {
		if strings.Contains(s, leak) {
			t.Errorf("wyciek %q: %s", leak, s)
		}
	}
	if !strings.Contains(s, `"hits":3`) || !strings.Contains(s, "Nieudane logowanie USER-") || len(ps) < 4 {
		t.Fatalf("wynik: %s (%d pseudonimów)", s, len(ps))
	}
	// Bez maskowania – bez zmian treści.
	plain, ps, _ := maskJSON(body, []byte("k"), AIMask{})
	if !strings.Contains(string(plain), "jan.kowalski") || len(ps) != 0 {
		t.Fatalf("bez maskowania: %s", plain)
	}
}

func (m *memAI) SaveAlertAnalysis(_ context.Context, a store.AlertAnalysis) (store.AlertAnalysis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.ID = int64(len(m.an) + 1)
	m.an = append([]store.AlertAnalysis{a}, m.an...)
	return a, nil
}
func (m *memAI) AlertAnalyses(_ context.Context, alertID int64, _ int) ([]store.AlertAnalysis, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.AlertAnalysis{}
	for _, a := range m.an {
		if a.AlertID == alertID {
			out = append(out, a)
		}
	}
	return out, nil
}
func (m *memAI) DeleteAlertAnalysis(_ context.Context, alertID, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, a := range m.an {
		if a.AlertID == alertID && a.ID == id {
			m.an = append(m.an[:i], m.an[i+1:]...)
			return nil
		}
	}
	return store.ErrNotFound
}
