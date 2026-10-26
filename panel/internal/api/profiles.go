// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"siem/panel/internal/api/store"
	"siem/panel/internal/perm"
)

// ProfileStore to profile uprawnień (implementuje store.PG). Opcjonalne:
// bez niego działają tylko profile wbudowane (dawne role).
type ProfileStore interface {
	Profiles(ctx context.Context) ([]store.Profile, error)
	SaveProfile(ctx context.Context, p store.Profile, by string, now time.Time) error
	DeleteProfile(ctx context.Context, id string) error
	ProfileUsers(ctx context.Context) (map[string]int, error)
}

// need to wymagane uprawnienie trasy; zero – wystarczy zalogowanie.
type need struct{ mod, level string }

func can(mod, level string) need { return need{mod, level} }

var loggedIn = need{}

// profileCache: profile z bazy (z uprawnieniami wbudowanych z kodu) –
// odświeżane co 30 s i po każdej zmianie w tym panelu.
type profileCache struct {
	mu   sync.Mutex
	at   time.Time
	byID map[string]store.Profile
}

func builtinProfiles() map[string]store.Profile {
	out := map[string]store.Profile{}
	for _, b := range perm.Builtin {
		out[b.ID] = store.Profile{ID: b.ID, Name: b.Name, Description: b.Description, Permissions: b.Perms(), Builtin: true}
	}
	return out
}

// profiles zwraca profile (id → profil); błąd bazy – ostatnie znane.
func (s *Server) profiles(ctx context.Context) map[string]store.Profile {
	c := &s.profileCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byID != nil && s.now().Sub(c.at) < 30*time.Second {
		return c.byID
	}
	if s.Profiles == nil {
		c.byID, c.at = builtinProfiles(), s.now()
		return c.byID
	}
	list, err := s.Profiles.Profiles(ctx)
	if err != nil {
		s.Log.Warn("reading permission profiles failed", "err", err)
		if c.byID == nil {
			return builtinProfiles()
		}
		return c.byID
	}
	byID := map[string]store.Profile{}
	for _, p := range list {
		if set := perm.BuiltinSet(p.ID); p.Builtin && set != nil {
			p.Permissions = set
		}
		if p.Permissions == nil {
			p.Permissions = map[string]string{}
		}
		byID[p.ID] = p
	}
	for id, p := range builtinProfiles() { // wbudowane zawsze (także przed migracją)
		if _, ok := byID[id]; !ok {
			byID[id] = p
		}
	}
	c.byID, c.at = byID, s.now()
	return byID
}

func (s *Server) dropProfileCache() {
	s.profileCache.mu.Lock()
	s.profileCache.byID = nil
	s.profileCache.mu.Unlock()
}

// permsOf: uprawnienia profilu konta (nieznany profil – żadnych).
func (s *Server) permsOf(ctx context.Context, profileID string) perm.Set {
	if p, ok := s.profiles(ctx)[profileID]; ok {
		return perm.Set(p.Permissions)
	}
	return perm.Set{}
}

// activeAdmins liczy aktywne konta z profilem administratora panelu
// (opcjonalnie z podmienionymi uprawnieniami jednego profilu – sprawdzenie
// zmiany profilu przed zapisem).
func (s *Server) activeAdmins(ctx context.Context, override map[string]perm.Set) (int, error) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		set, ok := override[u.Role]
		if !ok {
			set = s.permsOf(ctx, u.Role)
		}
		if !u.Disabled && set.Admin() {
			n++
		}
	}
	return n, nil
}

// profileExists: profil o tym identyfikatorze istnieje.
func (s *Server) profileExists(ctx context.Context, id string) bool {
	_, ok := s.profiles(ctx)[id]
	return ok
}

var profileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)

func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"modules": perm.Modules})
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	byID := s.profiles(r.Context())
	counts := map[string]int{}
	if s.Profiles != nil {
		var err error
		if counts, err = s.Profiles.ProfileUsers(r.Context()); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	out := make([]map[string]any, 0, len(byID))
	add := func(p store.Profile) {
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "description": p.Description, "permissions": p.Permissions,
			"builtin": p.Builtin, "users": counts[p.ID], "admin": perm.Set(p.Permissions).Admin(),
			"updated_by": p.UpdatedBy, "updated_at": p.UpdatedAt})
	}
	for _, b := range perm.Builtin {
		add(byID[b.ID])
	}
	var custom []store.Profile
	for _, p := range byID {
		if !p.Builtin {
			custom = append(custom, p)
		}
	}
	sortProfiles(custom)
	for _, p := range custom {
		add(p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out, "editable": s.Profiles != nil})
}

func sortProfiles(ps []store.Profile) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && strings.ToLower(ps[j].Name) < strings.ToLower(ps[j-1].Name); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

// saveProfile tworzy albo zmienia profil. Zawsze z hasłem (zmiana uprawnień);
// zmiana nie może zostawić panelu bez aktywnego administratora.
func (s *Server) saveProfile(w http.ResponseWriter, r *http.Request) {
	if s.Profiles == nil {
		writeError(w, http.StatusServiceUnavailable, "profiles_disabled", "profile uprawnień niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Permissions map[string]string `json:"permissions"`
		Password    string            `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.Description = strings.TrimSpace(req.Name), strings.TrimSpace(req.Description)
	set := perm.Set(req.Permissions)
	if set == nil {
		set = perm.Set{}
	}
	switch {
	case !profileIDPattern.MatchString(id):
		writeError(w, http.StatusBadRequest, "bad_id", "identyfikator profilu: 2–40 znaków, małe litery, cyfry, myślnik")
		return
	case perm.BuiltinSet(id) != nil:
		writeError(w, http.StatusConflict, "builtin", "profilu wbudowanego nie można zmienić – skopiuj go jako nowy")
		return
	case len([]rune(req.Name)) < 2 || len([]rune(req.Name)) > 64:
		writeError(w, http.StatusBadRequest, "bad_name", "nazwa profilu: 2–64 znaki")
		return
	case len(req.Description) > 300:
		writeError(w, http.StatusBadRequest, "bad_description", "opis jest za długi")
		return
	}
	if err := set.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_permissions", err)
		return
	}
	if !s.reauth(w, r, req.Password, "profile_save") {
		return
	}
	prev, existed := s.profiles(r.Context())[id]
	if existed && !set.Admin() {
		n, err := s.activeAdmins(r.Context(), map[string]perm.Set{id: set})
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if n == 0 {
			writeError(w, http.StatusConflict, "last_admin", "po tej zmianie żadne aktywne konto nie zarządzałoby panelem")
			return
		}
	}
	err := s.Profiles.SaveProfile(r.Context(), store.Profile{ID: id, Name: req.Name, Description: req.Description, Permissions: set},
		a.user.Username, s.now())
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "name_taken", "profil o tej nazwie już istnieje")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.dropProfileCache()
	details := map[string]any{"name": req.Name, "permissions": set, "created": !existed}
	if existed {
		details["previous"] = prev.Permissions
	}
	s.audit(r, &a.user, "profile_saved", id, details)
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	if s.Profiles == nil {
		writeError(w, http.StatusServiceUnavailable, "profiles_disabled", "profile uprawnień niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) || !s.reauth(w, r, req.Password, "profile_delete") {
		return
	}
	switch err := s.Profiles.DeleteProfile(r.Context(), id); {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "in_use", "profil ma przypisane konta lub ważne tokeny API – najpierw zmień im profil albo unieważnij tokeny")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego profilu (albo jest wbudowany)")
		return
	case err != nil:
		s.internalError(w, r, err)
		return
	}
	s.dropProfileCache()
	s.audit(r, &a.user, "profile_deleted", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
