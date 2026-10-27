// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"siem/internal/alerts"
)

// fakeLLM udaje endpoint zgodny z OpenAI: na pytanie wywołuje narzędzie
// tool, a po wyniku narzędzia odpowiada jego treścią („ECHO:”).
type fakeLLM struct {
	mu   sync.Mutex
	tool string
	auth []string
}

func (f *fakeLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if r.URL.Path == "/v1/models" {
		_, _ = w.Write([]byte(`{"data":[{"id":"qwen3-8b"}]}`))
		return
	}
	var body struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	last := body.Messages[len(body.Messages)-1]
	if last.Role != "tool" {
		b, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "",
			"tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": f.tool, "arguments": "{}"}}}}}}})
		_, _ = w.Write(b)
		return
	}
	b, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "ECHO:" + last.Content}}},
		"usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 5}})
	_, _ = w.Write(b)
}

type sseEvent struct {
	name string
	data map[string]any
}

func readSSE(t *testing.T, body io.Reader) []sseEvent {
	t.Helper()
	var out []sseEvent
	var name string
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			var d map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d); err != nil {
				t.Fatalf("SSE %q: %v", line, err)
			}
			out = append(out, sseEvent{name, d})
		}
	}
	return out
}

func eventOf(evs []sseEvent, name string) map[string]any {
	for _, e := range evs {
		if e.name == name {
			return e.data
		}
	}
	return nil
}

// Asystent: ustawienia (klucz nie wraca), pytanie z narzędziem przez sesję
// analityka – polityka AI (narzędzia, maskowanie), audyt, tylko sesja.
func TestAssistant(t *testing.T) {
	llm := &fakeLLM{tool: "list_agents"}
	model := httptest.NewServer(llm)
	t.Cleanup(model.Close)
	e, _ := newAIEnv(t)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")

	ask := func(q string) (int, []sseEvent) {
		code, _, res := a.do("POST", "/api/v1/ai/assistant/ask", map[string]any{"question": q, "lang": "pl"})
		if code != 200 {
			return code, nil
		}
		return code, readSSE(t, res.Body)
	}
	set := map[string]any{"enabled": true, "base_url": model.URL + "/v1", "model": "qwen3-8b", "max_steps": 3}
	// Asystent włączony, ale polityka AI wyłączona – odmowa.
	if code, out, _ := a.do("PUT", "/api/v1/ai/assistant", map[string]any{"assistant": set, "api_key": "sekret-klucz",
		"password": "bardzo-tajne-haslo-1"}); code != 200 || out["assistant"].(map[string]any)["has_api_key"] != true {
		t.Fatalf("ustawienia: %d %v", code, out)
	}
	if code, _ := ask("cześć"); code != 403 {
		t.Fatalf("polityka wyłączona: %d", code)
	}
	setPolicy(t, a, map[string]any{"enabled": true, "tools": map[string]bool{"system": true, "alerts": false},
		"mask": map[string]bool{"hosts": true, "ips": true}}, true)

	_, _, res := a.do("GET", "/api/v1/ai/assistant", nil)
	if raw, _ := io.ReadAll(res.Body); strings.Contains(string(raw), "sekret-klucz") {
		t.Fatalf("klucz API w odpowiedzi: %s", raw)
	}
	if code, out, _ := a.do("POST", "/api/v1/ai/assistant/models", map[string]any{"base_url": model.URL + "/v1"}); code != 200 ||
		len(out["models"].([]any)) != 1 {
		t.Fatalf("modele: %d %v", code, out)
	}
	if llm.auth[len(llm.auth)-1] != "Bearer sekret-klucz" {
		t.Fatalf("zapisany klucz przy liście modeli: %v", llm.auth)
	}

	code, evs := ask("Jakie mam agenty?")
	answer, _ := eventOf(evs, "answer")["text"].(string)
	tool := eventOf(evs, "tool")
	if code != 200 || tool["tool"] != "list_agents" || tool["fail"] == true || eventOf(evs, "done") == nil {
		t.Fatalf("pytanie: %d %v", code, evs)
	}
	if !strings.Contains(answer, "HOST-") || strings.Contains(answer, "PC-JANA") || strings.Contains(answer, "10.1.2.3") {
		t.Fatalf("maskowanie w odpowiedzi: %s", answer)
	}

	// Narzędzie wyłączone w polityce – model dostaje odmowę, przeglądarka znacznik błędu.
	llm.tool = "list_alerts"
	if _, evs = ask("A alerty?"); eventOf(evs, "tool")["fail"] != true {
		t.Fatalf("narzędzie poza polityką: %v", evs)
	}
	if !strings.Contains(strings.Join(e.st.actions(), ","), "ai_assistant_used") {
		t.Fatal("brak wpisu w audycie")
	}

	// Token API (nawet AI) nie korzysta z asystenta.
	_, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "ai", "profile": "admin", "kind": "ai",
		"acknowledge": true, "password": "bardzo-tajne-haslo-1"})
	if code, _ := e.bearer(out["secret"].(string), "POST", "/api/v1/ai/assistant/ask", map[string]any{"question": "x"}); code != 403 {
		t.Fatalf("token: %d", code)
	}
}

// oneAlert: magazyn alertów z jednym alertem (#7) – reszta metod niepotrzebna.
type oneAlert struct{ AlertStore }

func (oneAlert) Alert(_ context.Context, id int64) (alerts.Alert, error) {
	if id != 7 {
		return alerts.Alert{}, alerts.ErrNotFound
	}
	return alerts.Alert{ID: 7, RuleID: "r1", RuleTitle: "Brute force", Level: "high", Status: "open"}, nil
}
func (oneAlert) AlertEvents(context.Context, int64, int) ([]alerts.EventRef, error) { return nil, nil }
func (oneAlert) Activity(context.Context, int64) ([]alerts.Activity, error)         { return nil, nil }
func (oneAlert) Related(context.Context, alerts.Alert, time.Duration, int) ([]alerts.Alert, error) {
	return nil, nil
}
func (oneAlert) Rule(context.Context, string) (alerts.RuleInfo, error) {
	return alerts.RuleInfo{}, alerts.ErrNotFound
}
func (oneAlert) Rules(context.Context) ([]alerts.RuleInfo, []alerts.RuleError, error) {
	return nil, nil, nil
}

// „Analiza AI” alertu zostaje przy alercie: lista, usunięcie z audytem;
// dalsze pytania w rozmowie nie są zapisywane.
func TestAlertAnalysisSaved(t *testing.T) {
	llm := &fakeLLM{tool: "list_agents"}
	model := httptest.NewServer(llm)
	t.Cleanup(model.Close)
	e, ai := newAIEnvWith(t, func(s *Server) { s.Alerts = oneAlert{} })
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	a.do("PUT", "/api/v1/ai/assistant", map[string]any{"assistant": map[string]any{"enabled": true, "base_url": model.URL + "/v1",
		"model": "qwen3-8b"}, "password": "bardzo-tajne-haslo-1"})
	setPolicy(t, a, map[string]any{"enabled": true, "tools": map[string]bool{"system": true, "alerts": true}}, true)

	code, _, res := a.do("POST", "/api/v1/ai/assistant/ask", map[string]any{"alert_id": 7, "lang": "pl"})
	if code != 200 {
		t.Fatalf("analiza: %d", code)
	}
	done := eventOf(readSSE(t, res.Body), "done")
	if done == nil || done["analysis_id"] != float64(1) || done["alert_id"] != float64(7) {
		t.Fatalf("done: %v", done)
	}
	// Dalsza rozmowa – bez zapisu.
	_, _, res = a.do("POST", "/api/v1/ai/assistant/ask", map[string]any{"alert_id": 7, "question": "a dalej?",
		"history": []map[string]string{{"role": "user", "content": "x"}, {"role": "assistant", "content": "y"}}})
	if d := eventOf(readSSE(t, res.Body), "done"); d == nil || d["analysis_id"] != nil {
		t.Fatalf("rozmowa zapisana: %v", d)
	}
	code, out, _ := a.do("GET", "/api/v1/alerts/7/ai-analyses", nil)
	list, _ := out["analyses"].([]any)
	if code != 200 || len(list) != 1 {
		t.Fatalf("lista: %d %v", code, out)
	}
	an := list[0].(map[string]any)
	if an["created_by"] != "admin" || an["model"] != "qwen3-8b" || !strings.HasPrefix(an["answer"].(string), "ECHO:") {
		t.Fatalf("analiza: %v", an)
	}
	if code, _, _ := a.do("DELETE", "/api/v1/alerts/7/ai-analyses/1", nil); code != 200 || len(ai.an) != 0 {
		t.Fatalf("usunięcie: %d %v", code, ai.an)
	}
	if code, _, _ := a.do("DELETE", "/api/v1/alerts/7/ai-analyses/1", nil); code != 404 {
		t.Fatalf("ponowne usunięcie: %d", code)
	}
	if !strings.Contains(strings.Join(e.st.actions(), ","), "ai_analysis_deleted") {
		t.Fatal("brak wpisu w audycie")
	}
}

// Dokumentacja: dla zalogowanego i dla tokenu AI (zawsze przy włączonej
// polityce, bez maskowania – adresy z przykładów zostają).
func TestDocsSearch(t *testing.T) {
	e, _ := newAIEnv(t)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	code, out, _ := a.do("GET", "/api/v1/docs/search?q=reguła+korelacyjna&lang=pl", nil)
	secs, _ := out["sections"].([]any)
	if code != 200 || len(secs) == 0 || secs[0].(map[string]any)["doc"] != "reguly.md" {
		t.Fatalf("szukanie: %d %v", code, out)
	}
	setPolicy(t, a, map[string]any{"enabled": true, "tools": map[string]bool{"alerts": false}, "mask": map[string]bool{"ips": true}}, true)
	_, tok, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "ai", "profile": "admin", "kind": "ai",
		"acknowledge": true, "password": "bardzo-tajne-haslo-1"})
	code, out = e.bearer(tok["secret"].(string), "GET", "/api/v1/docs/search?q=adres+IP+syslog", nil)
	if code != 200 || strings.Contains(fmt.Sprint(out), "IP-") {
		t.Fatalf("token AI: %d %v", code, out)
	}
}
