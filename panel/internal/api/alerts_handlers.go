package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
)

// AlertStore to alerty i reguły Gjallarhorna (implementuje alerts.PG).
type AlertStore interface {
	Alerts(ctx context.Context, f alerts.Filter) ([]alerts.Alert, error)
	Alert(ctx context.Context, id int64) (alerts.Alert, error)
	AlertEvents(ctx context.Context, id int64, limit int) ([]alerts.EventRef, error)
	Summarize(ctx context.Context, now time.Time) (alerts.Summary, error)
	Rules(ctx context.Context) ([]alerts.RuleInfo, []alerts.RuleError, error)
	Rule(ctx context.Context, id string) (alerts.RuleInfo, error)
	SetStatus(ctx context.Context, id int64, status, by, reason string, now time.Time) (alerts.Alert, error)
}

func (s *Server) alertsEnabled(w http.ResponseWriter) bool {
	if s.Alerts == nil {
		writeError(w, http.StatusServiceUnavailable, "alerts_disabled", "moduł alertów wyłączony w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) alertsError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, alerts.ErrNotConfigured):
		writeError(w, http.StatusConflict, "detector_not_configured", "detektor (Gjallarhorn) jeszcze nie działał")
	case errors.Is(err, alerts.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego alertu")
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	q := r.URL.Query()
	f := alerts.Filter{Status: q.Get("status"), Level: q.Get("level"), RuleID: q.Get("rule"), Limit: 100}
	if f.Status != "" && f.Status != "open" && f.Status != "acknowledged" && f.Status != "closed" {
		writeError(w, http.StatusBadRequest, "bad_status", "status: open, acknowledged albo closed")
		return
	}
	if v := q.Get("before"); v != "" {
		f.Before, _ = strconv.ParseInt(v, 10, 64)
	}
	list, err := s.Alerts.Alerts(r.Context(), f)
	if errors.Is(err, alerts.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": []alerts.Alert{}, "configured": false})
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if list == nil {
		list = []alerts.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": list, "configured": true})
}

func (s *Server) alertsSummary(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	sum, err := s.Alerts.Summarize(r.Context(), s.now())
	if errors.Is(err, alerts.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "summary": sum})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	a, err := s.Alerts.Alert(r.Context(), id)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	evs, err := s.Alerts.AlertEvents(r.Context(), id, 50)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if evs == nil {
		evs = []alerts.EventRef{}
	}
	resp := map[string]any{"alert": a, "events": evs}
	if rule, err := s.Alerts.Rule(r.Context(), a.RuleID); err == nil {
		resp["rule"] = rule
	}
	writeJSON(w, http.StatusOK, resp)
}

// setAlertStatus: potwierdzenie (wzięcie do analizy) albo zamknięcie
// z powodem. Pełny workflow (przypisanie, komentarze) – etap 5.
func (s *Server) setAlertStatus(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case !slices.Contains([]string{"open", "acknowledged", "closed"}, req.Status):
		writeError(w, http.StatusBadRequest, "bad_status", "status: open, acknowledged albo closed")
		return
	case req.Status == "closed" && (len([]rune(req.Reason)) < 3 || len(req.Reason) > 1000):
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód zamknięcia (np. fałszywy alarm, wyjaśnione, incydent)")
		return
	}
	upd, err := s.Alerts.SetStatus(r.Context(), id, req.Status, a.user.Username, req.Reason, s.now())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "alert_status_changed", strconv.FormatInt(id, 10), map[string]any{
		"status": req.Status, "reason": req.Reason, "rule": upd.RuleID})
	writeJSON(w, http.StatusOK, map[string]any{"alert": upd})
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	rules, errs, err := s.Alerts.Rules(r.Context())
	if errors.Is(err, alerts.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []alerts.RuleInfo{}, "errors": []alerts.RuleError{}, "configured": false})
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if rules == nil {
		rules = []alerts.RuleInfo{}
	}
	if errs == nil {
		errs = []alerts.RuleError{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "errors": errs, "configured": true})
}
