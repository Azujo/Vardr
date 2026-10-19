package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

// Tokeny deinstalacji w pamięci (ta sama semantyka co store.PG).
type memToken struct {
	store.UninstallToken
	hash string
}

var memTokens = map[*memStore][]*memToken{}

func (m *memStore) CreateUninstallToken(_ context.Context, agentID, hash, reason, by string, expires time.Time) (store.UninstallToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, t := range memTokens[m] {
		if t.AgentID == agentID && t.UsedAt == nil && t.RevokedAt == nil {
			t.RevokedAt, t.RevokedBy = &now, by
		}
	}
	m.nextID++
	t := &memToken{UninstallToken: store.UninstallToken{ID: m.nextID, AgentID: agentID, TokenID: contract.UninstallTokenID(hash),
		Reason: reason, CreatedBy: by, CreatedAt: now, ExpiresAt: expires, State: "active"}, hash: hash}
	memTokens[m] = append(memTokens[m], t)
	return t.UninstallToken, nil
}

func (m *memStore) UninstallTokens(_ context.Context, agentID string, now time.Time) ([]store.UninstallToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.UninstallToken
	for _, t := range memTokens[m] {
		if t.AgentID != agentID {
			continue
		}
		x := t.UninstallToken
		switch {
		case x.UsedAt != nil:
			x.State = "used"
		case x.RevokedAt != nil:
			x.State = "revoked"
		case now.After(x.ExpiresAt):
			x.State = "expired"
		}
		out = append([]store.UninstallToken{x}, out...)
	}
	return out, nil
}

func (m *memStore) ActiveUninstallTokens(_ context.Context, agentID string) ([]contract.UninstallToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []contract.UninstallToken
	for _, t := range memTokens[m] {
		if t.AgentID == agentID && t.UsedAt == nil && t.RevokedAt == nil && m.now().Before(t.ExpiresAt) {
			out = append(out, contract.UninstallToken{ID: t.TokenID, Hash: t.hash, ExpiresAt: t.ExpiresAt.UTC()})
		}
	}
	return out, nil
}

func (m *memStore) RevokeUninstallToken(_ context.Context, agentID string, id int64, by string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, t := range memTokens[m] {
		if t.ID == id && t.AgentID == agentID && t.UsedAt == nil && t.RevokedAt == nil {
			t.RevokedAt, t.RevokedBy = &now, by
			return true, nil
		}
	}
	return false, nil
}

func TestUninstallTokens(t *testing.T) {
	e, _ := newEnrollEnv(t)
	admin := e.client("10.0.0.1")
	admin.login("admin", "haslo-admina-123")
	now := e.clock
	e.st.agents = map[string]store.Agent{"agt-pc1": {ID: "agt-pc1", LastSeen: now, Status: json.RawMessage(`{}`)}}

	base := configRequest(e, "agt-pc1", "")
	var cfg0 contract.AgentConfig
	json.Unmarshal(base.Body.Bytes(), &cfg0)

	// Powód i hasło są wymagane.
	if code, out, _ := admin.do("POST", "/api/v1/agents/agt-pc1/uninstall-tokens", map[string]any{"reason": "x"}); code != 400 {
		t.Fatalf("bez powodu: %d %v", code, out)
	}
	if code, out, _ := admin.do("POST", "/api/v1/agents/agt-pc1/uninstall-tokens", map[string]any{"reason": "reinstalacja"}); code != 403 || out["error"] != "reauth_required" {
		t.Fatalf("bez hasła: %d %v", code, out)
	}
	if code, _, _ := admin.do("POST", "/api/v1/agents/agt-nieznany/uninstall-tokens", map[string]any{"reason": "reinstalacja", "password": "haslo-admina-123"}); code != 404 {
		t.Fatalf("nieznany agent: %d", code)
	}
	code, out, _ := admin.do("POST", "/api/v1/agents/agt-pc1/uninstall-tokens", map[string]any{"reason": "ZGL-17 reinstalacja", "password": "haslo-admina-123"})
	if code != 201 {
		t.Fatalf("token: %d %v", code, out)
	}
	token := out["token"].(string)
	item := out["item"].(map[string]any)
	if len(token) != 23 || item["state"] != "active" || strings.Contains(item["token_id"].(string), token[:5]) {
		t.Fatalf("token: %q %v", token, item)
	}

	// Agent dostaje skrót w konfiguracji; wersja zmienia się tylko przyrostkiem.
	w := configRequest(e, "agt-pc1", base.Header().Get("ETag"))
	var cfg contract.AgentConfig
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if w.Code != 200 || len(cfg.UninstallTokens) != 1 || cfg.UninstallTokens[0].Hash != contract.UninstallHash("agt-pc1", token) ||
		contract.BaseVersion(cfg.Version) != cfg0.Version || cfg.Version == cfg0.Version {
		t.Fatalf("konfiguracja z tokenem: %d %+v", w.Code, cfg)
	}
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("token jawnym tekstem w konfiguracji agenta")
	}
	// Panel uznaje konfigurację z przyrostkiem za zastosowaną.
	if _, st := agentConfigState(json.RawMessage(`{"config":{"version":"`+cfg.Version+`"}}`), cfg0.Version); st != "applied" {
		t.Fatalf("stan konfiguracji: %s", st)
	}
	// Inny agent nie dostaje tokenu.
	var other contract.AgentConfig
	json.Unmarshal(configRequest(e, "agt-pc2", "").Body.Bytes(), &other)
	if len(other.UninstallTokens) != 0 {
		t.Fatal("token u innego agenta")
	}

	// Nowy token unieważnia poprzedni; unieważnienie usuwa go z konfiguracji.
	_, out2, _ := admin.do("POST", "/api/v1/agents/agt-pc1/uninstall-tokens", map[string]any{"reason": "drugi", "password": "haslo-admina-123"})
	id2 := itoa(int64(out2["item"].(map[string]any)["id"].(float64)))
	_, list, _ := admin.do("GET", "/api/v1/agents/agt-pc1/uninstall-tokens", nil)
	toks := list["tokens"].([]any)
	if len(toks) != 2 || toks[0].(map[string]any)["state"] != "active" || toks[1].(map[string]any)["state"] != "revoked" {
		t.Fatalf("lista: %v", toks)
	}
	if code, _, _ := admin.do("POST", "/api/v1/agents/agt-pc1/uninstall-tokens/"+id2+"/revoke", nil); code != 204 {
		t.Fatalf("unieważnienie: %d", code)
	}
	cfg = contract.AgentConfig{}
	json.Unmarshal(configRequest(e, "agt-pc1", "").Body.Bytes(), &cfg)
	if len(cfg.UninstallTokens) != 0 || cfg.Version != cfg0.Version {
		t.Fatalf("po unieważnieniu: %+v", cfg)
	}
	if !e.st.hasAudit("agent_uninstall_token_created") || !e.st.hasAudit("agent_uninstall_token_revoked") {
		t.Fatal("brak wpisu w audycie")
	}
}

func TestAgentViewProtection(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	g := store.AgentGroup{ID: 1, Name: "Stacje", Profile: "workstation"}
	st := `{"protection":{"enabled":true,"service":"open","error":"odmowa dostępu","events":[` +
		`{"id":"a","at":"2026-10-12T11:00:00Z","kind":"bad_token"},{"id":"b","at":"2026-10-12T11:30:00Z","kind":"stop_token","token_id":"x"},` +
		`{"id":"c","at":"2026-10-10T11:00:00Z","kind":"stop"}]}}`
	v := viewAgent(store.Agent{ID: "agt-1", LastSeen: now, Status: json.RawMessage(st)}, g, now)
	if v.Protection != "open" || v.Tamper != 1 || len(v.Problems) != 2 {
		t.Fatalf("%+v", v)
	}
	// Agent zatrzymany: powód z ostatniego heartbeatu zamiast „brak heartbeatu”.
	v = viewAgent(store.Agent{ID: "agt-1", LastSeen: now.Add(-time.Hour), Status: json.RawMessage(`{"stopping":"stop"}`)}, g, now)
	if v.State != "offline" || !strings.Contains(v.Problems[0], "zatrzymany (bez tokenu)") {
		t.Fatalf("%+v", v.Problems)
	}
	v = viewAgent(store.Agent{ID: "agt-1", LastSeen: now.Add(-time.Hour), Status: json.RawMessage(`{"stopping":"shutdown"}`)}, g, now)
	if !strings.Contains(v.Problems[0], "wyłączony") || v.Protection != "unknown" {
		t.Fatalf("%+v", v)
	}
	// Wycofany (certyfikat unieważniony po deinstalacji tokenem) – stan, nie problem.
	v = viewAgent(store.Agent{ID: "agt-1", LastSeen: now.Add(-time.Hour), CertRevoked: true,
		Status: json.RawMessage(`{"stopping":"uninstall_token"}`)}, g, now)
	if v.State != "retired" || len(v.Problems) != 0 {
		t.Fatalf("wycofany: %+v", v)
	}
}

func (m *memStore) hasAudit(action string) bool {
	for _, a := range m.actions() {
		if a == action {
			return true
		}
	}
	return false
}
