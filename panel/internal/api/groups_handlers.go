package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

type groupRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Profile     string               `json:"profile"`
	Limits      contract.AgentLimits `json:"limits"`
}

func (req *groupRequest) validate(w http.ResponseWriter) bool {
	req.Name, req.Description = strings.TrimSpace(req.Name), strings.TrimSpace(req.Description)
	cfg := contract.AgentConfig{Profile: req.Profile, Limits: req.Limits}
	switch {
	case req.Name == "" || len(req.Name) > 128:
		writeError(w, http.StatusBadRequest, "bad_name", "nazwa grupy: 1–128 znaków")
		return false
	case len(req.Description) > 512:
		writeError(w, http.StatusBadRequest, "bad_description", "opis jest za długi")
		return false
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "bad_config", err.Error())
		return false
	}
	return true
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Store.ListGroups(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	type view struct {
		store.AgentGroup
		ConfigVersion string `json:"config_version"`
	}
	out := make([]view, 0, len(groups))
	for _, g := range groups {
		out = append(out, view{g, g.Config().Version})
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	var req groupRequest
	if !readJSON(w, r, &req) || !req.validate(w) {
		return
	}
	g, err := s.Store.CreateGroup(r.Context(), store.AgentGroup{Name: req.Name, Description: req.Description, Profile: req.Profile, Limits: req.Limits})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "grupa o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "group_created", g.Name, map[string]any{"profile": g.Profile, "limits": g.Limits})
	writeJSON(w, http.StatusCreated, map[string]any{"group": g})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator grupy")
		return
	}
	var req groupRequest
	if !readJSON(w, r, &req) || !req.validate(w) {
		return
	}
	before, err := s.Store.GroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiej grupy")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	g, err := s.Store.UpdateGroup(r.Context(), store.AgentGroup{ID: id, Name: req.Name, Description: req.Description, Profile: req.Profile, Limits: req.Limits})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "grupa o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "group_updated", g.Name, map[string]any{
		"profile": map[string]string{"from": before.Profile, "to": g.Profile}, "limits": g.Limits, "config_version": g.Config().Version})
	writeJSON(w, http.StatusOK, map[string]any{"group": g})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator grupy")
		return
	}
	g, err := s.Store.GroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiej grupy")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	switch err := s.Store.DeleteGroup(r.Context(), id); {
	case errors.Is(err, store.ErrInUse):
		writeError(w, http.StatusConflict, "in_use", "nie można usunąć grupy domyślnej ani grupy z przypisanymi agentami")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "group_deleted", g.Name, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setAgentGroup(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return
	}
	var req struct {
		GroupID int64 `json:"group_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	g, err := s.Store.GroupByID(r.Context(), req.GroupID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "bad_group", "nie ma takiej grupy")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.AssignAgent(r.Context(), id, g.ID); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "agent_group_changed", id, map[string]any{"group": g.Name})
	writeJSON(w, http.StatusOK, map[string]any{"group": g, "config_version": g.Config().Version})
}

// agentConfig: agent pobiera swoją konfigurację (mTLS). If-None-Match z
// wersją, którą agent już ma → 304 bez treści.
func (s *Server) agentConfig(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		writeError(w, http.StatusUnauthorized, "no_client_cert", "konfiguracja wymaga certyfikatu agenta")
		return
	}
	cert := r.TLS.PeerCertificates[0]
	agentID := cert.Subject.CommonName
	if !agentIDPattern.MatchString(agentID) {
		writeError(w, http.StatusForbidden, "bad_identity", "niepoprawny identyfikator agenta w certyfikacie")
		return
	}
	if c, err := s.Store.AgentCertBySerial(r.Context(), cert.SerialNumber.Text(16)); err == nil && c.RevokedAt != nil {
		writeError(w, http.StatusForbidden, "revoked", "certyfikat agenta został unieważniony")
		return
	}
	g, err := s.Store.GroupForAgent(r.Context(), agentID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cfg := g.Config()
	etag := `"` + cfg.Version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// agentConfigState porównuje wersję zastosowaną przez agenta (z heartbeatu)
// z oczekiwaną (z grupy).
func agentConfigState(status json.RawMessage, expected string) (applied, state string) {
	var st struct {
		Config struct {
			Version string `json:"version"`
		} `json:"config"`
	}
	_ = json.Unmarshal(status, &st)
	applied = st.Config.Version
	switch {
	case applied == "":
		state = "unknown" // starszy agent albo jeszcze nie pobrał konfiguracji
	case applied == expected:
		state = "applied"
	default:
		state = "pending"
	}
	return applied, state
}
