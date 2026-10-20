package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{2,64}$`)

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	mfa := map[int64]time.Time{}
	if s.mfaEnabled() {
		if mfa, err = s.MFA.MFAEnabledUsers(r.Context()); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "mfa": mfa, "mfa_available": s.mfaEnabled(),
		"mfa_policy": s.mfaPolicy(r.Context())})
}

// createdUser zawiera hasło startowe – pokazywane administratorowi jeden raz.
type createdUser struct {
	User         store.User `json:"user"`
	TempPassword string     `json:"temp_password"`
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	var req struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Username, req.DisplayName = strings.TrimSpace(req.Username), strings.TrimSpace(req.DisplayName)
	switch {
	case !usernamePattern.MatchString(req.Username):
		writeError(w, http.StatusBadRequest, "bad_username", "login: 2–64 znaki, litery, cyfry, kropka, myślnik, podkreślenie")
		return
	case !store.ValidRole(req.Role):
		writeError(w, http.StatusBadRequest, "bad_role", "rola musi być jedną z: admin, analyst, viewer")
		return
	case len(req.DisplayName) > 128:
		writeError(w, http.StatusBadRequest, "bad_display_name", "nazwa wyświetlana jest za długa")
		return
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	u, err := s.Store.CreateUser(r.Context(), store.User{
		Username: req.Username, DisplayName: req.DisplayName, Role: req.Role, PasswordHash: hash, MustChangePassword: true,
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "konto o tym loginie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "user_created", u.Username, map[string]any{"role": u.Role})
	writeJSON(w, http.StatusCreated, createdUser{User: u, TempPassword: temp})
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator konta")
		return
	}
	var req struct {
		DisplayName *string `json:"display_name"`
		Role        *string `json:"role"`
		Disabled    *bool   `json:"disabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Role != nil && !store.ValidRole(*req.Role) {
		writeError(w, http.StatusBadRequest, "bad_role", "rola musi być jedną z: admin, analyst, viewer")
		return
	}
	if req.DisplayName != nil {
		*req.DisplayName = strings.TrimSpace(*req.DisplayName)
		if len(*req.DisplayName) > 128 {
			writeError(w, http.StatusBadRequest, "bad_display_name", "nazwa wyświetlana jest za długa")
			return
		}
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego konta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if id == a.user.ID && req.Disabled != nil && *req.Disabled {
		writeError(w, http.StatusConflict, "self", "nie można wyłączyć własnego konta")
		return
	}
	// Ostatni aktywny administrator nie może stracić roli ani zostać wyłączony.
	losesAdmin := target.Role == store.RoleAdmin && !target.Disabled &&
		((req.Role != nil && *req.Role != store.RoleAdmin) || (req.Disabled != nil && *req.Disabled))
	if losesAdmin {
		n, err := s.Store.CountActiveAdmins(r.Context())
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if n <= 1 {
			writeError(w, http.StatusConflict, "last_admin", errLastAdmin.Error())
			return
		}
	}
	u, err := s.Store.UpdateUser(r.Context(), id, store.UserPatch{DisplayName: req.DisplayName, Role: req.Role, Disabled: req.Disabled})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	details := map[string]any{}
	if req.Role != nil && *req.Role != target.Role {
		details["role"] = map[string]string{"from": target.Role, "to": *req.Role}
	}
	if req.Disabled != nil && *req.Disabled != target.Disabled {
		details["disabled"] = *req.Disabled
	}
	if req.DisplayName != nil && *req.DisplayName != target.DisplayName {
		details["display_name"] = *req.DisplayName
	}
	// Zmiana roli lub wyłączenie konta działa od razu: kończymy jego sesje.
	if _, roleChanged := details["role"]; roleChanged || (req.Disabled != nil && *req.Disabled) {
		if err := s.Store.DeleteUserSessions(r.Context(), id, ""); err != nil {
			s.Log.Error("usunięcie sesji konta nieudane", "user_id", id, "err", err)
		}
	}
	s.audit(r, &a.user, "user_updated", u.Username, details)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator konta")
		return
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego konta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	temp := auth.TempPassword()
	hash, err := auth.HashPassword(temp)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.SetPassword(r.Context(), id, hash, true); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.Store.DeleteUserSessions(r.Context(), id, ""); err != nil {
		s.Log.Error("usunięcie sesji konta nieudane", "user_id", id, "err", err)
	}
	s.audit(r, &a.user, "password_reset", target.Username, nil)
	target.MustChangePassword = true
	writeJSON(w, http.StatusOK, createdUser{User: target, TempPassword: temp})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := s.Store.ListAudit(r.Context(), limit, before)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
