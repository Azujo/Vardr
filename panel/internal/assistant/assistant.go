// SPDX-License-Identifier: AGPL-3.0-or-later

// Package assistant to asystent AI panelu (wersja 1.5): pętla agenta na
// endpoincie zgodnym z OpenAI (LM Studio, Ollama, vLLM, usługi chmurowe)
// z narzędziami Vardra tylko do odczytu (internal/mcp).
//
// Model nie ma narzędzi zmieniających cokolwiek – nawet udany prompt
// injection z logów może najwyżej wprowadzić w błąd treścią odpowiedzi.
package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"siem/internal/mcp"
)

// Client to klient endpointu zgodnego z OpenAI (/chat/completions, /models).
type Client struct {
	BaseURL string // np. http://192.168.88.10:1234/v1
	Model   string
	APIKey  string // opcjonalny (LM Studio, Ollama – bez klucza)
	HTTP    *http.Client
}

// Message to wiadomość rozmowy (format OpenAI).
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolCall to wywołanie narzędzia przez model.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type toolSpec struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// Usage: zużycie tokenów (sumowane po krokach).
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content          string     `json:"content"`
			ReasoningContent string     `json:"reasoning_content"`
			ToolCalls        []ToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("connection to the model failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return fmt.Errorf("model endpoint: HTTP %d: %s", resp.StatusCode, msg)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("model endpoint: invalid response: %w", err)
	}
	return nil
}

// Models zwraca identyfikatory modeli dostępnych w endpoincie.
func (c *Client) Models(ctx context.Context) ([]string, error) {
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/models", nil, &out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Data))
	for _, m := range out.Data {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

func (c *Client) chat(ctx context.Context, msgs []Message, tools []toolSpec) (chatResponse, error) {
	body := map[string]any{"model": c.Model, "messages": msgs, "stream": false}
	if len(tools) > 0 {
		body["tools"] = tools
		body["tool_choice"] = "auto"
	}
	var out chatResponse
	if err := c.do(ctx, http.MethodPost, "/chat/completions", body, &out); err != nil {
		return out, err
	}
	if len(out.Choices) == 0 {
		return out, errors.New("model endpoint: empty response")
	}
	return out, nil
}

// Tools to źródło narzędzi (mcp.Server).
type Tools interface {
	Tools(ctx context.Context) []mcp.Tool
	Call(ctx context.Context, name string, args map[string]any) mcp.ToolResult
}

// Event to krok pracy asystenta dla przeglądarki (postęp na żywo).
type Event struct {
	Type string         `json:"type"` // step, tool, answer
	Step int            `json:"step,omitempty"`
	Tool string         `json:"tool,omitempty"`
	Args map[string]any `json:"args,omitempty"`
	Fail bool           `json:"fail,omitempty"` // narzędzie zwróciło błąd (np. odmowa polityki)
	Text string         `json:"text,omitempty"`
}

// Result to podsumowanie przebiegu (do audytu).
type Result struct {
	Answer string
	Steps  int
	Tools  []string
	Usage  Usage
	Took   time.Duration
}

// Run prowadzi rozmowę: model → narzędzia → model…, najwyżej maxSteps
// wywołań modelu z narzędziami; potem prosi o odpowiedź z tym, co ma.
func Run(ctx context.Context, c *Client, tools Tools, msgs []Message, maxSteps int, emit func(Event)) (Result, error) {
	start := time.Now()
	var res Result
	var specs []toolSpec
	for _, t := range tools.Tools(ctx) {
		var sp toolSpec
		sp.Type = "function"
		sp.Function.Name, sp.Function.Description, sp.Function.Parameters = t.Name, t.Description, t.InputSchema
		specs = append(specs, sp)
	}
	for step := 1; ; step++ {
		final := step > maxSteps
		if final {
			msgs = append(msgs, Message{Role: "user", Content: "Tool call limit reached. Answer now with what you have and list what is left to check."})
		}
		emit(Event{Type: "step", Step: step})
		var resp chatResponse
		var err error
		if final {
			resp, err = c.chat(ctx, msgs, nil)
		} else {
			resp, err = c.chat(ctx, msgs, specs)
		}
		res.Steps = step
		res.Usage.PromptTokens += resp.Usage.PromptTokens
		res.Usage.CompletionTokens += resp.Usage.CompletionTokens
		if err != nil {
			res.Took = time.Since(start)
			return res, err
		}
		m := resp.Choices[0].Message
		if len(m.ToolCalls) == 0 || final {
			res.Answer = CleanAnswer(m.Content)
			if res.Answer == "" {
				res.Answer = CleanAnswer(m.ReasoningContent)
			}
			res.Took = time.Since(start)
			emit(Event{Type: "answer", Text: res.Answer})
			return res, nil
		}
		msgs = append(msgs, Message{Role: "assistant", Content: m.Content, ToolCalls: m.ToolCalls})
		for _, tc := range m.ToolCalls {
			args := map[string]any{}
			var out mcp.ToolResult
			if a := strings.TrimSpace(tc.Function.Arguments); a != "" {
				if err := json.Unmarshal([]byte(a), &args); err != nil {
					out = mcp.ToolResult{IsError: true, Content: []map[string]any{{"type": "text", "text": "invalid JSON arguments: " + err.Error()}}}
				}
			}
			if out.Content == nil {
				out = tools.Call(ctx, tc.Function.Name, args)
			}
			res.Tools = append(res.Tools, tc.Function.Name)
			emit(Event{Type: "tool", Step: step, Tool: tc.Function.Name, Args: args, Fail: out.IsError})
			var text strings.Builder
			for _, c := range out.Content {
				if s, ok := c["text"].(string); ok {
					text.WriteString(s)
				}
			}
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Content: text.String()})
		}
	}
}

var thinkRe = regexp.MustCompile(`(?s)<think>.*?</think>`)

// CleanAnswer usuwa rozumowanie modeli „myślących” (<think>…</think>).
func CleanAnswer(s string) string {
	s = thinkRe.ReplaceAllString(s, "")
	if i := strings.Index(s, "</think>"); i >= 0 { // otwarcie ucięte przez serwer
		s = s[i+len("</think>"):]
	}
	return strings.TrimSpace(s)
}
