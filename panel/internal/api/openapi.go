// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"siem/internal/svc"
)

// Opis OpenAPI 3.1 budowany z tabeli tras (routes.go): ścieżki, metody,
// wymagane uprawnienie (x-vardr-permission), dostępność dla tokenów
// (x-vardr-token). Parametry zapytań opisane są dla tras, z których
// korzystają integracje (alerty, zdarzenia, incydenty, audyt); treści
// żądań i odpowiedzi – ogólnie (obiekt JSON). Opis jest publiczny jak
// dokumentacja w repozytorium – nie zawiera danych instalacji.

type oaParam struct {
	Name, In, Desc string
	Enum           []string
}

// queryDocs: parametry zapytań wybranych tras (wzorzec trasy → parametry).
var queryDocs = map[string][]oaParam{
	"GET /api/v1/alerts": {
		{Name: "status", Desc: "open, acknowledged or closed", Enum: []string{"open", "acknowledged", "closed"}},
		{Name: "level", Desc: "rule level", Enum: []string{"informational", "low", "medium", "high", "critical"}},
		{Name: "since", Desc: "only alerts seen in the last period", Enum: []string{"24h", "7d", "30d"}},
		{Name: "rule", Desc: "rule ID"},
		{Name: "host", Desc: "computer name"},
		{Name: "user", Desc: "account or person"},
		{Name: "assignee", Desc: "assigned user; `me` – the caller"},
		{Name: "engine", Desc: "detection engine"},
		{Name: "technique", Desc: "MITRE ATT&CK technique (T1110 also matches sub-techniques)"},
		{Name: "tactic", Desc: "MITRE ATT&CK tactic"},
		{Name: "q", Desc: "text search"},
		{Name: "before", Desc: "paging: alerts with an ID lower than this (100 per page)"},
	},
	"GET /api/v1/events": {
		{Name: "q", Desc: "query in the Mímir language, e.g. `event.code:4625 AND user.name:jan*`"},
		{Name: "from", Desc: "range start, RFC 3339 (default: one hour ago)"},
		{Name: "to", Desc: "range end, RFC 3339 (default: now); the range is at most 31 days"},
		{Name: "limit", Desc: "rows per page"},
		{Name: "before_ts", Desc: "paging cursor: timestamp of the last row"},
		{Name: "before_id", Desc: "paging cursor: ID of the last row"},
		{Name: "source", Desc: "`replay` – events replayed from the archive", Enum: []string{"replay"}},
	},
	"GET /api/v1/events/histogram": {
		{Name: "q", Desc: "query in the Mímir language"},
		{Name: "from", Desc: "range start, RFC 3339"},
		{Name: "to", Desc: "range end, RFC 3339"},
	},
	"GET /api/v1/events/{id}": {
		{Name: "ts", Desc: "event timestamp, RFC 3339 (from the search result)"},
		{Name: "source", Desc: "`replay` – replayed event", Enum: []string{"replay"}},
	},
	"GET /api/v1/incidents": {
		{Name: "scope", Desc: "list scope (open incidents by default)"},
	},
	"GET /api/v1/audit": {
		{Name: "limit", Desc: "entries per page (max 500)"},
		{Name: "before", Desc: "paging: entries with an ID lower than this"},
	},
}

var pathParam = regexp.MustCompile(`\{([a-z]+)\}`)

// handlerName: nazwa metody handlera (listAlerts) z wartości funkcji.
func handlerName(h http.HandlerFunc) string {
	n := runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
	n = strings.TrimSuffix(n, "-fm")
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return n
}

// summaryOf: „listAlerts” → „List alerts”, „listAPITokens” → „List API
// tokens” (skróty – ciąg wielkich liter – zostają wielkimi).
func summaryOf(name string) string {
	rs := []rune(name)
	var words []string
	start := 0
	for i := 1; i < len(rs); i++ {
		lowerToUpper := unicode.IsLower(rs[i-1]) && unicode.IsUpper(rs[i])
		acronymEnd := unicode.IsUpper(rs[i-1]) && unicode.IsUpper(rs[i]) && i+1 < len(rs) && unicode.IsLower(rs[i+1])
		if lowerToUpper || acronymEnd {
			words = append(words, string(rs[start:i]))
			start = i
		}
	}
	words = append(words, string(rs[start:]))
	for i, w := range words {
		if w != strings.ToUpper(w) || len(w) == 1 { // nie skrót
			w = strings.ToLower(w)
		}
		if i == 0 {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		words[i] = w
	}
	return strings.Join(words, " ")
}

// buildOpenAPI składa dokument z tabeli tras.
func buildOpenAPI(routes []route) map[string]any {
	paths := map[string]map[string]any{}
	jsonObj := map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}
	errResp := map[string]any{"description": "error", "content": map[string]any{"application/json": map[string]any{
		"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
	for _, rt := range routes {
		method, path, _ := strings.Cut(rt.pattern, " ")
		name := handlerName(rt.h)
		tag := strings.SplitN(strings.TrimPrefix(path, "/api/v1/"), "/", 2)[0]
		op := map[string]any{
			"operationId": name,
			"summary":     summaryOf(name),
			"tags":        []string{tag},
			"responses":   map[string]any{"200": map[string]any{"description": "OK", "content": jsonObj}, "4XX": errResp},
		}
		var params []map[string]any
		for _, m := range pathParam.FindAllStringSubmatch(path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		for _, p := range queryDocs[rt.pattern] {
			schema := map[string]any{"type": "string"}
			if p.Enum != nil {
				schema["enum"] = p.Enum
			}
			params = append(params, map[string]any{"name": p.Name, "in": "query", "description": p.Desc, "schema": schema})
		}
		if params != nil {
			op["parameters"] = params
		}
		if method != http.MethodGet {
			op["requestBody"] = map[string]any{"required": false, "content": jsonObj}
		}
		token := rt.need != public && (rt.need != loggedIn || rt.flags&allowToken != 0)
		switch {
		case rt.need == public:
			op["security"] = []any{}
			op["x-vardr-permission"] = "public"
		case rt.need == loggedIn:
			op["x-vardr-permission"] = "signed-in"
		default:
			op["x-vardr-permission"] = rt.need.mod + ":" + rt.need.level
		}
		if rt.need != public {
			sec := []any{map[string]any{"session": []string{}}}
			if token {
				sec = append([]any{map[string]any{"token": []string{}}}, sec...)
			}
			op["security"] = sec
		}
		op["x-vardr-token"] = token
		if paths[path] == nil {
			paths[path] = map[string]any{}
		}
		paths[path][strings.ToLower(method)] = op
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "Vardr API",
			"version": svc.Version,
			"description": "API of the Vardr panel (Hliðskjálf). Programs authenticate with an API token " +
				"(`Authorization: Bearer vardr_…`) created in the panel (Users → API tokens); the token has a permission " +
				"profile like an account, without account management. `x-vardr-permission` is the required module:level, " +
				"`x-vardr-token` – whether the operation is available to tokens. Errors: `{error, message, message_en}`.",
			"license": map[string]any{"name": "AGPL-3.0-or-later", "identifier": "AGPL-3.0-or-later"},
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"token":   map[string]any{"type": "http", "scheme": "bearer", "description": "API token (vardr_…)"},
				"session": map[string]any{"type": "apiKey", "in": "cookie", "name": cookieName, "description": "panel session (with the X-CSRF-Token header for changes)"},
			},
			"schemas": map[string]any{
				"Error": map[string]any{"type": "object", "required": []string{"error", "message"}, "properties": map[string]any{
					"error":      map[string]any{"type": "string", "description": "stable error code"},
					"message":    map[string]any{"type": "string", "description": "description (Polish)"},
					"message_en": map[string]any{"type": "string", "description": "description in English, when available"},
				}},
			},
		},
	}
}

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, buildOpenAPI(s.routes()))
}
