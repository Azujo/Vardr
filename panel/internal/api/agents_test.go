package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"siem/panel/internal/api/store"
)

func (m *memStore) ListAgents(context.Context) ([]store.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Agent
	for _, a := range m.agents {
		out = append(out, a)
	}
	return out, nil
}
func (m *memStore) AgentByID(_ context.Context, id string) (store.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return a, store.ErrNotFound
	}
	return a, nil
}
func (m *memStore) DeleteAgent(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.agents, id)
	return nil
}

func TestAgentsListAndDetail(t *testing.T) {
	e := newEnv(t)
	e.addUser("ola", store.RoleViewer, "haslo-oli-12345", false)
	e.addUser("admin", store.RoleAdmin, "haslo-admina-123", false)
	now := e.clock
	soon := now.Add(5 * 24 * time.Hour)
	later := now.Add(80 * 24 * time.Hour)
	e.st.agents = map[string]store.Agent{
		"agt-ok": {ID: "agt-ok", Hostname: "PC01", LastSeen: now.Add(-30 * time.Second), CertNotAfter: &later,
			Status: json.RawMessage(`{"server":{"healthy":true},"counters":{"accepted":120,"read":125},
				"channels":[{"name":"System","state":"ok"},{"name":"Sysmon","state":"not_found"}]}`)},
		"agt-bad": {ID: "agt-bad", Hostname: "PC02", LastSeen: now.Add(-time.Minute), CertNotAfter: &soon,
			Status: json.RawMessage(`{"server":{"healthy":false,"last_error":"HTTP 503"},"counters":{"quarantined":3},
				"channels":[{"name":"Security","state":"access_denied"}],"warnings":["a","ostatnie"]}`)},
		"agt-off": {ID: "agt-off", LastSeen: now.Add(-10 * time.Minute), Status: json.RawMessage(`{}`)},
	}
	c := e.client("10.0.0.1")
	c.login("ola", "haslo-oli-12345")
	code, out, _ := c.do("GET", "/api/v1/agents", nil)
	if code != 200 {
		t.Fatalf("lista: %d %v", code, out)
	}
	sum := out["summary"].(map[string]any)
	if sum["total"] != 3.0 || sum["online"] != 2.0 || sum["offline"] != 1.0 || sum["with_problems"] != 2.0 {
		t.Fatalf("podsumowanie: %v", sum)
	}
	agents := out["agents"].([]any)
	first := agents[0].(map[string]any)
	last := agents[2].(map[string]any)
	if first["id"] != "agt-bad" || last["id"] != "agt-ok" || len(last["problems"].([]any)) != 0 {
		t.Fatalf("kolejność lub problemy: %v", agents)
	}
	probs := strings.Join(toStrings(first["problems"]), "|")
	for _, want := range []string{"certyfikat wygasa za 5 dni", "kanał Security: brak dostępu", "HTTP 503", "3 zdarzeń w kwarantannie"} {
		if !strings.Contains(probs, want) {
			t.Errorf("brak problemu %q w %q", want, probs)
		}
	}
	if first["last_warning"] != "ostatnie" || first["warnings"] != 2.0 {
		t.Errorf("ostrzeżenia: %v", first)
	}
	off := agents[1].(map[string]any)
	if off["state"] != "offline" || !strings.Contains(toStrings(off["problems"])[0], "brak heartbeatu od 10 min") {
		t.Errorf("offline: %v", off)
	}

	code, out, _ = c.do("GET", "/api/v1/agents/agt-ok", nil)
	if code != 200 || out["status"].(map[string]any)["counters"].(map[string]any)["accepted"] != 120.0 {
		t.Fatalf("szczegóły: %d %v", code, out)
	}
	if code, _, _ := c.do("GET", "/api/v1/agents/nie-ma", nil); code != 404 {
		t.Fatalf("brak agenta: %d", code)
	}
	if code, _, _ := c.do("DELETE", "/api/v1/agents/agt-off", nil); code != 403 {
		t.Fatalf("viewer nie usuwa agentów: %d", code)
	}
	a := e.client("10.0.0.2")
	a.login("admin", "haslo-admina-123")
	if code, _, _ := a.do("DELETE", "/api/v1/agents/agt-off", nil); code != 204 {
		t.Fatalf("usunięcie: %d", code)
	}
	if got := e.st.actions(); got[len(got)-1] != "agent_removed" {
		t.Fatalf("audyt: %v", got)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
