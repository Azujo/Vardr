// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mcp to minimalna implementacja Model Context Protocol dla Vardra
// (wersja 1.4): JSON-RPC 2.0 – initialize, tools/list, tools/call, ping –
// po stdio (program vardr-mcp) i po Streamable HTTP (endpoint panelu
// /api/v1/mcp). Bez zewnętrznej biblioteki – tylko narzędzia, bez zasobów
// i promptów.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
)

// supportedVersions: wersje protokołu MCP (najnowsza pierwsza).
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Tool to narzędzie MCP.
type Tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

// ToolResult to wynik wywołania narzędzia.
type ToolResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError"`
}

func textResult(text string, isErr bool) ToolResult {
	return ToolResult{Content: []map[string]any{{"type": "text", "text": text}}, IsError: isErr}
}

// Handler to logika serwera: lista narzędzi i ich wywołanie.
type Handler interface {
	Tools(ctx context.Context) []Tool
	Call(ctx context.Context, name string, args map[string]any) ToolResult
	Instructions() string
}

// Info: nazwa i wersja serwera w odpowiedzi na initialize.
type Info struct {
	Name, Title, Version string
}

// Serve obsługuje protokół po stdio (jedna wiadomość na linię) aż do końca wejścia.
func Serve(ctx context.Context, in io.Reader, out io.Writer, h Handler, info Info, log *slog.Logger) error {
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	send := func(r rpcResponse) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(r); err != nil {
			log.Error("writing the MCP response failed", "err", err)
		}
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			send(parseError())
			continue
		}
		if resp, ok := handle(ctx, h, info, req); ok {
			send(resp)
		}
	}
	return sc.Err()
}

func parseError() rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}}
}

// handle: odpowiedź na żądanie (ok=false dla powiadomienia – bez odpowiedzi).
func handle(ctx context.Context, h Handler, info Info, req rpcRequest) (rpcResponse, bool) {
	result, rerr := dispatch(ctx, h, info, req)
	if len(req.ID) == 0 {
		return rpcResponse{}, false
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	return resp, true
}

func dispatch(ctx context.Context, h Handler, info Info, req rpcRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := supportedVersions[0]
		if slices.Contains(supportedVersions, p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": info.Name, "title": info.Title, "version": info.Version},
			"instructions":    h.Instructions(),
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": h.Tools(ctx)}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: -32602, Message: "invalid params"}
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		return h.Call(ctx, p.Name, p.Arguments), nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found"} // bez nazwy – nie odbijamy danych wejściowych
}

// maxHTTPBody: największe żądanie JSON-RPC po HTTP.
const maxHTTPBody = 1 << 20

// ServeHTTP obsługuje jedno żądanie transportu Streamable HTTP: POST
// z wiadomością (albo paczką wiadomości) JSON-RPC, odpowiedź JSON. Serwer
// bezstanowy – bez sesji (Mcp-Session-Id) i bez strumienia SSE; GET
// obsługuje wywołujący (405). Uwierzytelnienie i uprawnienia sprawdza
// wywołujący przed ServeHTTP.
func ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler, info Info) {
	// Ochrona przed DNS rebinding: żądanie ze strony WWW innego pochodzenia.
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			httpError(w, http.StatusForbidden, "origin not allowed")
			return
		}
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(supportedVersions, v) {
		httpError(w, http.StatusBadRequest, "unsupported MCP-Protocol-Version")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody+1))
	if err != nil {
		httpError(w, http.StatusBadRequest, "reading the request failed")
		return
	}
	if len(body) > maxHTTPBody {
		httpError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	body = bytes.TrimSpace(body)
	batch := len(body) > 0 && body[0] == '['
	var reqs []rpcRequest
	if batch {
		err = json.Unmarshal(body, &reqs)
	} else {
		var one rpcRequest
		err = json.Unmarshal(body, &one)
		reqs = []rpcRequest{one}
	}
	if err != nil || len(reqs) == 0 {
		writeJSON(w, http.StatusBadRequest, parseError())
		return
	}
	var out []rpcResponse
	for _, req := range reqs {
		if resp, ok := handle(r.Context(), h, info, req); ok {
			out = append(out, resp)
		}
	}
	switch {
	case len(out) == 0: // same powiadomienia
		w.WriteHeader(http.StatusAccepted)
	case batch:
		writeJSON(w, http.StatusOK, out)
	default:
		writeJSON(w, http.StatusOK, out[0])
	}
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32600, Message: msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "encoding the response failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
