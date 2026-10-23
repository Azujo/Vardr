// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"slices"
	"time"

	"siem/panel/internal/syslang"
)

// SettingStore to ustawienia panelu (panel_settings) – store.PG.
type SettingStore interface {
	Setting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value, by string, now time.Time) error
}

// systemLanguage: język treści wychodzących poza panel (powiadomienia,
// szkice zgłoszeń NIS2) – syslang.Default bez ustawienia.
func (s *Server) systemLanguage(ctx context.Context) string {
	return s.SysLang.Get(ctx)
}

func (s *Server) languageSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"language": s.systemLanguage(r.Context()), "supported": syslang.Supported,
		"editable": s.Settings != nil})
}

// setLanguageSettings zmienia język systemu (administrator panelu, w audycie).
func (s *Server) setLanguageSettings(w http.ResponseWriter, r *http.Request) {
	if s.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings_disabled", "ustawienia niedostępne w tej konfiguracji")
		return
	}
	a := current(r)
	var req struct {
		Language string `json:"language"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !slices.Contains(syslang.Supported, req.Language) {
		writeError(w, http.StatusBadRequest, "bad_language", "nieobsługiwany język")
		return
	}
	prev := s.systemLanguage(r.Context())
	if err := s.Settings.SetSetting(r.Context(), syslang.Key, req.Language, a.user.Username, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.SysLang.Set(req.Language)
	s.audit(r, &a.user, "system_language_changed", req.Language, map[string]any{"from": prev, "to": req.Language})
	writeJSON(w, http.StatusOK, map[string]any{"language": req.Language})
}
