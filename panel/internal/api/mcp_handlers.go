// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"net/url"

	"siem/internal/mcp"
	"siem/internal/svc"
	"siem/panel/internal/api/store"
)

// mcpPattern: serwer MCP w panelu (Streamable HTTP) – dla klientów AI na
// serwerach i w sieci (Open WebUI, LibreChat, n8n…), bez programu vardr-mcp.
const mcpPattern = "POST /api/v1/mcp"

// mcpHTTP: endpoint MCP, tylko dla tokenu rodzaju AI. Narzędzia wykonują
// wewnętrzne zapytania do tras API z tym samym tokenem – każde przechodzi
// przez tokenAuthed: polityka AI, maskowanie, limity, audyt odmów
// i historia zapytań działają dokładnie tak jak dla vardr-mcp.
func (s *Server) mcpHTTP(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	if a.token == nil || a.token.Kind != store.TokenAI {
		writeError(w, http.StatusForbidden, "mcp_ai_token_only", "serwer MCP przyjmuje tylko token API rodzaju AI")
		return
	}
	srv := &mcp.Server{C: internalCaller{s: s, outer: r}, Log: s.Log}
	mcp.ServeHTTP(w, r, srv, mcp.Info{Name: "vardr", Title: "Vardr SIEM (read-only)", Version: svc.Version})
}

// mcpNoStream: GET – serwer nie wysyła wiadomości z własnej inicjatywy
// (bez strumienia SSE); specyfikacja Streamable HTTP przewiduje wtedy 405.
func (s *Server) mcpNoStream(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "serwer MCP Vardra przyjmuje tylko POST (Streamable HTTP, bez strumienia SSE)")
}

// internalCaller wykonuje zapytanie GET narzędzia przez drzewo tras panelu,
// z nagłówkiem Authorization i adresem klienta z zapytania MCP.
type internalCaller struct {
	s     *Server
	outer *http.Request
}

func (c internalCaller) Get(ctx context.Context, path string, q url.Values, out any) error {
	u := path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.outer.Header.Get("Authorization"))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vardr-mcp-http")
	req.RemoteAddr, req.Host, req.TLS = c.outer.RemoteAddr, c.outer.Host, c.outer.TLS
	bw := &bufferWriter{header: http.Header{}}
	c.s.mux.ServeHTTP(bw, req)
	status := bw.status
	if status == 0 {
		status = http.StatusOK
	}
	return mcp.DecodeResponse(status, bw.buf.Bytes(), out)
}
