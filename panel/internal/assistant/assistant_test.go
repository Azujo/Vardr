// SPDX-License-Identifier: AGPL-3.0-or-later

package assistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"siem/internal/mcp"
)

type fakeTools struct{ calls []string }

func (f *fakeTools) Tools(context.Context) []mcp.Tool {
	return []mcp.Tool{{Name: "list_alerts", Description: "alerts", InputSchema: map[string]any{"type": "object"}}}
}

func (f *fakeTools) Call(_ context.Context, name string, args map[string]any) mcp.ToolResult {
	f.calls = append(f.calls, name+":"+args["status"].(string))
	return mcp.ToolResult{Content: []map[string]any{{"type": "text", "text": `{"alerts":[{"id":7}]}`}}}
}

// fakeModel: najpierw wywołuje narzędzie, potem odpowiada (z <think>);
// always – zawsze wywołuje narzędzie (test limitu kroków).
func fakeModel(t *testing.T, always bool) (*httptest.Server, *[]map[string]any) {
	var reqs []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"qwen3-8b"},{"id":"gpt-oss-20b"}]}`))
			return
		}
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(400)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		reqs = append(reqs, body)
		msgs := body["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if _, hasTools := body["tools"]; hasTools && (always || last["role"] != "tool") {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","tool_calls":[{"id":"c1","type":"function",
				"function":{"name":"list_alerts","arguments":"{\"status\":\"open\"}"}}]},"finish_reason":"tool_calls"}],
				"usage":{"prompt_tokens":100,"completion_tokens":10}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"<think>hmm</think>\n## Podsumowanie\nAlert [alert:7]."},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":200,"completion_tokens":20}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestRun(t *testing.T) {
	srv, reqs := fakeModel(t, false)
	c := &Client{BaseURL: srv.URL + "/v1", Model: "qwen3-8b", APIKey: "k", HTTP: srv.Client()}
	tools := &fakeTools{}
	var events []string
	res, err := Run(context.Background(), c, tools, []Message{{Role: "system", Content: "s"}, {Role: "user", Content: "q"}}, 5,
		func(e Event) { events = append(events, e.Type+":"+e.Tool) })
	if err != nil {
		t.Fatal(err)
	}
	if res.Answer != "## Podsumowanie\nAlert [alert:7]." || res.Steps != 2 || res.Usage.PromptTokens != 300 || len(tools.calls) != 1 {
		t.Fatalf("wynik: %+v, narzędzia %v", res, tools.calls)
	}
	if got := strings.Join(events, ","); got != "step:,tool:list_alerts,step:,answer:" {
		t.Fatalf("zdarzenia: %s", got)
	}
	// Druga prośba: wynik narzędzia wraca do modelu jako wiadomość „tool”.
	msgs := (*reqs)[1]["messages"].([]any)
	if tm := msgs[len(msgs)-1].(map[string]any); tm["role"] != "tool" || tm["tool_call_id"] != "c1" || !strings.Contains(tm["content"].(string), `"id":7`) {
		t.Fatalf("wiadomość narzędzia: %v", tm)
	}
	if ids, err := c.Models(context.Background()); err != nil || len(ids) != 2 {
		t.Fatalf("modele: %v %v", ids, err)
	}
}

// Limit kroków: po maxSteps model dostaje prośbę o odpowiedź bez narzędzi.
func TestRunStepLimit(t *testing.T) {
	srv, reqs := fakeModel(t, true)
	c := &Client{BaseURL: srv.URL + "/v1", Model: "m", APIKey: "k", HTTP: srv.Client()}
	res, err := Run(context.Background(), c, &fakeTools{}, []Message{{Role: "user", Content: "q"}}, 2, func(Event) {})
	if err != nil || res.Steps != 3 || len(res.Tools) != 2 || res.Answer == "" {
		t.Fatalf("limit: %+v %v", res, err)
	}
	if _, hasTools := (*reqs)[2]["tools"]; hasTools {
		t.Fatal("ostatnie wywołanie z narzędziami")
	}
}

func TestCleanAnswer(t *testing.T) {
	for in, want := range map[string]string{
		"<think>a\nb</think>\n\nOdp.": "Odp.",
		"tekst</think> Odp.":          "Odp.",
		"  zwykła odpowiedź ":         "zwykła odpowiedź",
	} {
		if got := CleanAnswer(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
