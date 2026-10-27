// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"

	"siem/docs"
)

const docsSearchPattern = "GET /api/v1/docs/search"

// docsSearch: wyszukiwanie w dokumentacji Vardra (narzędzie search_docs
// asystenta AI i serwera MCP); puste zapytanie – spis rozdziałów.
func (s *Server) docsSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	lang := r.URL.Query().Get("lang")
	if lang != "en" {
		lang = "pl"
	}
	if len(q) > 300 {
		writeError(w, http.StatusBadRequest, "bad_request", "zapytanie: do 300 znaków")
		return
	}
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"contents": docs.Contents(lang)})
		return
	}
	res := docs.Search(q, lang, 3, 2500)
	if res == nil {
		res = []docs.Section{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sections": res})
}
