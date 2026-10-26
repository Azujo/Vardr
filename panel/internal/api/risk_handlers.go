// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/risk"
)

// RiskStore to wyniki i ustawienia scoringu ryzyka (implementuje alerts.PG).
// Wyniki liczy siem-detector; panel czyta je i zmienia ustawienia.
type RiskStore interface {
	RiskConfig(ctx context.Context) (risk.Config, error)
	SetRiskConfig(ctx context.Context, c risk.Config, by string, now time.Time) error
	RiskScores(ctx context.Context, typ, minLevel string, limit int) ([]alerts.RiskScore, error)
	RiskScoreOf(ctx context.Context, typ, entity string) (alerts.RiskScore, error)
	RiskLevelCounts(ctx context.Context) (map[string]map[string]int, error)
}

func (s *Server) riskEnabled(w http.ResponseWriter) bool {
	if s.Risk == nil {
		writeError(w, http.StatusServiceUnavailable, "alerts_disabled", "moduł alertów wyłączony w konfiguracji siem-api")
		return false
	}
	return true
}

func riskType(w http.ResponseWriter, typ string) bool {
	if typ != risk.User && typ != risk.Host {
		writeError(w, http.StatusBadRequest, "bad_type", "rodzaj: user albo host")
		return false
	}
	return true
}

// listRisk: ranking osób albo komputerów (od najwyższego wyniku) i liczba
// encji na każdym poziomie.
func (s *Server) listRisk(w http.ResponseWriter, r *http.Request) {
	if !s.riskEnabled(w) {
		return
	}
	q := r.URL.Query()
	typ, level := q.Get("type"), q.Get("level")
	if typ == "" {
		typ = risk.User
	}
	if !riskType(w, typ) {
		return
	}
	if level != "" && !slices.Contains(risk.Levels, level) {
		writeError(w, http.StatusBadRequest, "bad_level", "nieznany poziom")
		return
	}
	scores, err := s.Risk.RiskScores(r.Context(), typ, level, 500)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	counts, err := s.Risk.RiskLevelCounts(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	cfg, err := s.Risk.RiskConfig(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scores": scores, "counts": counts, "enabled": cfg.Enabled,
		"thresholds": cfg.Thresholds})
}

// getRisk: wynik jednej osoby albo komputera (klucz bez wielkości liter);
// brak wyniku – zero (nie błąd: osoba bez alertów ma ryzyko niskie).
func (s *Server) getRisk(w http.ResponseWriter, r *http.Request) {
	if !s.riskEnabled(w) {
		return
	}
	typ := r.PathValue("type")
	if !riskType(w, typ) {
		return
	}
	// Ten sam klucz co w scoringu (komputer bez domeny: PC1.firma.local = pc1).
	entity := strings.ToLower(strings.TrimSpace(r.PathValue("entity")))
	if typ == risk.Host {
		entity, _ = risk.HostKey(entity)
	}
	if entity == "" || len(entity) > 512 {
		writeError(w, http.StatusBadRequest, "bad_entity", "niepoprawna osoba albo komputer")
		return
	}
	sc, err := s.Risk.RiskScoreOf(r.Context(), typ, entity)
	if errors.Is(err, alerts.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"score": nil})
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"score": sc})
}

func (s *Server) getRiskConfig(w http.ResponseWriter, r *http.Request) {
	if !s.riskEnabled(w) {
		return
	}
	cfg, err := s.Risk.RiskConfig(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "default": risk.Default(), "resolutions": risk.Resolutions})
}

// setRiskConfig zmienia ustawienia scoringu – zawsze z hasłem: wyłączenie,
// podniesienie progów albo mniej punktów ukrywa ryzykowne osoby.
func (s *Server) setRiskConfig(w http.ResponseWriter, r *http.Request) {
	if !s.riskEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Config   risk.Config `json:"config"`
		Password string      `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	cfg := req.Config
	slices.Sort(cfg.CriticalGroups)
	cfg.CriticalGroups = slices.Compact(cfg.CriticalGroups)
	var users []string
	for _, u := range cfg.PrivilegedUsers {
		if u = strings.TrimSpace(u); u != "" && !slices.Contains(users, u) {
			users = append(users, u)
		}
	}
	cfg.PrivilegedUsers = users
	if err := cfg.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_risk_config", err)
		return
	}
	if !s.reauth(w, r, req.Password, "risk_config") {
		return
	}
	prev, err := s.Risk.RiskConfig(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if err := s.Risk.SetRiskConfig(r.Context(), cfg, a.user.Username, s.now()); err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "risk_config_changed", "risk", map[string]any{"config": cfg, "previous": prev})
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg})
}
