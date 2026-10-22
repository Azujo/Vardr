// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"siem/internal/urd"
)

// Obsługa niezgodności archiwum: pliki na dysku nieznane spisowi (np. po
// przywróceniu kopii bazy). Administrator decyduje: przyjąć do spisu
// (archiwizator sprawdza format, sumy i łańcuch) albo odłożyć do
// kwarantanny (plik zachowany poza łańcuchem). Wynik weryfikacji, która
// niezgodność wykryła, zostaje bez zmian w historii; decyzja jest osobnym
// wpisem (urd.recoveries, plik w archiwum recoveries/, audyt panelu).

// maxRecoveryPaths: najwięcej plików w jednej decyzji.
const maxRecoveryPaths = 500

var recoveryActions = map[string]string{
	"adopt":      "przyjęcie do archiwum",
	"quarantine": "odłożenie do kwarantanny",
}

func (s *Server) requestRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Action   string   `json:"action"`
		Paths    []string `json:"paths"`
		Reason   string   `json:"reason"`
		Password string   `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case recoveryActions[req.Action] == "":
		writeError(w, http.StatusBadRequest, "bad_action", "decyzja: adopt (przyjęcie) albo quarantine (kwarantanna)")
		return
	case len(req.Paths) == 0 || len(req.Paths) > maxRecoveryPaths:
		writeError(w, http.StatusBadRequest, "bad_paths", "wskaż od 1 do 500 plików")
		return
	case len([]rune(req.Reason)) < 10 || len(req.Reason) > 1000:
		writeError(w, http.StatusBadRequest, "bad_reason", "opisz przyczynę niezgodności (co najmniej 10 znaków) – trafi do spisu archiwum i audytu")
		return
	}
	o, err := s.Archive.Overview(r.Context())
	if err != nil {
		s.archiveError(w, r, err)
		return
	}
	lv := o.LastVerification
	if lv == nil || len(lv.Unknown) == 0 {
		writeError(w, http.StatusConflict, "no_unknown", "ostatnia weryfikacja nie zgłosiła nieznanych plików")
		return
	}
	// Tylko pliki zgłoszone przez ostatnią weryfikację (nie dowolne ścieżki).
	for _, p := range req.Paths {
		if !urd.ValidUnknownPath(p) || !slices.Contains(lv.Unknown, p) {
			writeError(w, http.StatusBadRequest, "bad_paths", "plik "+p+" nie jest na liście nieznanych plików z ostatniej weryfikacji")
			return
		}
	}
	if !s.reauth(w, r, req.Password, "archive_recovery") {
		return
	}
	id, err := s.Archive.RequestRecovery(r.Context(), req.Action, a.user.Username, req.Reason, req.Paths, lv.ID)
	if err != nil {
		s.archiveError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_recovery_requested", "urd", map[string]any{"id": id, "action": req.Action, "files": len(req.Paths),
		"paths": req.Paths, "reason": req.Reason, "verification": lv.ID})
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id,
		"message": recoveryActions[req.Action] + " zlecone – archiwizator wykona je w ciągu minuty i od razu zweryfikuje archiwum"})
}

func (s *Server) archiveError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, urd.ErrNotConfigured) {
		writeError(w, http.StatusConflict, "archive_not_configured", "archiwizator jeszcze nie działał")
		return
	}
	s.internalError(w, r, err)
}
