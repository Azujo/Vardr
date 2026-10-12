package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

// Tokeny deinstalacji agenta (ochrona agenta, etap 8). Token jest
// jednorazowy i związany z jednym agentem; panel pokazuje go tylko raz,
// w bazie i na komputerze jest wyłącznie skrót. Wygenerowanie wymaga roli
// administratora, powodu i ponownego podania hasła (wpis w audycie).

const (
	uninstallTokenDefault = 24 * time.Hour
	uninstallTokenMax     = 7 * 24 * time.Hour
)

func (s *Server) agentForProtection(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return "", false
	}
	if _, err := s.Store.AgentByID(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego agenta")
		return "", false
	} else if err != nil {
		s.internalError(w, r, err)
		return "", false
	}
	return id, true
}

func (s *Server) listUninstallTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := s.agentForProtection(w, r)
	if !ok {
		return
	}
	items, err := s.Store.UninstallTokens(r.Context(), id, s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if items == nil {
		items = []store.UninstallToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
}

func (s *Server) createUninstallToken(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := s.agentForProtection(w, r)
	if !ok {
		return
	}
	var req struct {
		Reason   string `json:"reason"`
		Hours    int    `json:"hours"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód (np. numer zgłoszenia: wymiana komputera, reinstalacja)")
		return
	}
	valid := uninstallTokenDefault
	if req.Hours != 0 {
		valid = time.Duration(req.Hours) * time.Hour
	}
	if valid < time.Hour || valid > uninstallTokenMax {
		writeError(w, http.StatusBadRequest, "bad_hours", "ważność tokenu: 1–168 godzin")
		return
	}
	if !s.reauth(w, r, req.Password, "agent_uninstall_token") {
		return
	}
	token, err := contract.NewUninstallToken()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	t, err := s.Store.CreateUninstallToken(r.Context(), id, contract.UninstallHash(id, token), req.Reason, a.user.Username,
		s.now().Add(valid))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "agent_uninstall_token_created", id, map[string]any{"token_id": t.TokenID, "reason": req.Reason,
		"expires_at": t.ExpiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "item": t})
}

func (s *Server) revokeUninstallToken(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := s.agentForProtection(w, r)
	if !ok {
		return
	}
	tid, err := strconv.ParseInt(r.PathValue("tid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator tokenu")
		return
	}
	done, err := s.Store.RevokeUninstallToken(r.Context(), id, tid, a.user.Username)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !done {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego aktywnego tokenu")
		return
	}
	s.audit(r, &a.user, "agent_uninstall_token_revoked", id, map[string]any{"id": tid})
	w.WriteHeader(http.StatusNoContent)
}
