// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func mcpCall(e *env, token string, id int, method string, params map[string]any) (int, map[string]any) {
	return e.bearer(token, "POST", "/api/v1/mcp", map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

// Endpoint MCP w panelu: tylko token AI, narzędzia według polityki,
// wyniki narzędzi zamaskowane (raz) i zapisane w historii jak zapytania API.
func TestMCPEndpoint(t *testing.T) {
	e, _ := newAIEnv(t)
	a := e.client("10.0.0.1")
	a.login("admin", "bardzo-tajne-haslo-1")
	_, out, _ := a.do("POST", "/api/v1/api-tokens", map[string]any{"name": "open-webui", "profile": "admin", "kind": "ai",
		"acknowledge": true, "password": "bardzo-tajne-haslo-1"})
	ai := out["secret"].(string)
	integ := createToken(t, a, "skrypt", "admin", 30)

	// Polityka wyłączona – odmowa już na wejściu.
	if code, out := mcpCall(e, ai, 1, "initialize", nil); code != 403 || out["error"] != "ai_disabled" {
		t.Fatalf("polityka wyłączona: %d %v", code, out)
	}
	setPolicy(t, a, map[string]any{"enabled": true, "tools": map[string]bool{"system": true, "alerts": false},
		"mask": map[string]bool{"hosts": true, "ips": true}}, true)

	if code, out := mcpCall(e, ai, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"}); code != 200 ||
		out["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "vardr" {
		t.Fatalf("initialize: %d %v", code, out)
	}
	_, out = mcpCall(e, ai, 2, "tools/list", nil)
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"list_agents"`) || strings.Contains(string(raw), `"list_alerts"`) {
		t.Fatalf("narzędzia według polityki: %s", raw)
	}
	code, out := mcpCall(e, ai, 3, "tools/call", map[string]any{"name": "list_agents"})
	res := out["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if code != 200 || res["isError"] != false || strings.Contains(text, "PC-JANA") || strings.Contains(text, "10.1.2.3") ||
		!strings.Contains(text, "HOST-") || strings.Contains(text, "HOST-HOST") {
		t.Fatalf("list_agents przez MCP: %d %s", code, text)
	}
	// Narzędzie wyłączone w polityce – odmowa wewnętrznego zapytania, model dostaje wyjaśnienie.
	_, out = mcpCall(e, ai, 4, "tools/call", map[string]any{"name": "list_alerts"})
	if res := out["result"].(map[string]any); res["isError"] != true {
		t.Fatalf("narzędzie wyłączone: %v", res)
	}

	if code, out := mcpCall(e, integ, 5, "tools/list", nil); code != 403 || out["error"] != "mcp_ai_token_only" {
		t.Fatalf("token integracji: %d %v", code, out)
	}
	if code, _ := e.bearer(ai, "GET", "/api/v1/mcp", nil); code != 405 {
		t.Fatalf("GET: %d", code)
	}
	if code, _, _ := a.do("POST", "/api/v1/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); code != 403 {
		t.Fatalf("sesja panelu: %d", code)
	}
}
