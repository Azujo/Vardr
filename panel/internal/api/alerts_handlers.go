// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"siem/internal/risk"
)

// AlertStore to alerty i reguły Gjallarhorna (implementuje alerts.PG).
type AlertStore interface {
	Alerts(ctx context.Context, f alerts.Filter) ([]alerts.Alert, int, error)
	Alert(ctx context.Context, id int64) (alerts.Alert, error)
	AlertEvents(ctx context.Context, id int64, limit int) ([]alerts.EventRef, error)
	Summarize(ctx context.Context, now time.Time) (alerts.Summary, error)
	Rules(ctx context.Context) ([]alerts.RuleInfo, []alerts.RuleError, error)
	Rule(ctx context.Context, id string) (alerts.RuleInfo, error)
	SetStatus(ctx context.Context, id int64, status, by, reason, resolution string, now time.Time) (alerts.Alert, error)
	SetStatusMany(ctx context.Context, ids []int64, status, by, reason, resolution string, now time.Time) ([]alerts.Alert, error)
	Assign(ctx context.Context, id int64, assignee, by string, now time.Time) (alerts.Alert, error)
	AddNote(ctx context.Context, id int64, by, text string, now time.Time) error
	Activity(ctx context.Context, id int64) ([]alerts.Activity, error)
	Related(ctx context.Context, a alerts.Alert, window time.Duration, limit int) ([]alerts.Alert, error)
	AlertCountsByRule(ctx context.Context, since time.Time) (map[string]alerts.RuleAlertCount, error)
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
	case errors.Is(err, alerts.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego alertu")
	case errors.Is(err, alerts.ErrNotConfigured):
		writeError(w, http.StatusServiceUnavailable, "not_configured", "detekcja nie jest skonfigurowana (siem-detector nie działał)")
	default:
		s.internalError(w, r, err)
	}
}

var alertStatuses = []string{"open", "acknowledged", "closed"}

var sinceRanges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	q := r.URL.Query()
	f := alerts.Filter{Status: q.Get("status"), Level: q.Get("level"), RuleID: q.Get("rule"), Host: q.Get("host"),
		User: q.Get("user"), Assignee: q.Get("assignee"), Engine: q.Get("engine"), Text: strings.TrimSpace(q.Get("q")), Limit: 100}
	if f.Assignee == "me" {
		f.Assignee = a.user.Username
	}
	switch {
	case f.Status != "" && !slices.Contains(alertStatuses, f.Status):
		writeError(w, http.StatusBadRequest, "bad_status", "status: open, acknowledged albo closed")
		return
	case f.Level != "" && !slices.Contains([]string{"informational", "low", "medium", "high", "critical"}, f.Level):
		writeError(w, http.StatusBadRequest, "bad_level", "nieznany poziom")
		return
	case len(f.Host) > 255 || len(f.User) > 255 || len(f.Text) > 255 || len(f.Assignee) > 128:
		writeError(w, http.StatusBadRequest, "bad_filter", "za długi filtr")
		return
	}
	if v := q.Get("since"); v != "" {
		d, ok := sinceRanges[v]
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_since", "zakres: 24h, 7d albo 30d")
			return
		}
		t := s.now().Add(-d)
		f.Since = &t
	}
	if v := q.Get("before"); v != "" {
		f.Before, _ = strconv.ParseInt(v, 10, 64)
	}
	// MITRE ATT&CK: alerty reguł danej techniki (T1110 – także podtechnik) albo taktyki.
	if tech, tac := strings.ToUpper(strings.TrimSpace(q.Get("technique"))), strings.TrimSpace(q.Get("tactic")); tech != "" || tac != "" {
		if len(tech) > 16 || len(tac) > 64 {
			writeError(w, http.StatusBadRequest, "bad_filter", "za długi filtr")
			return
		}
		ids, err := s.attackRuleFilter(r.Context(), tech, tac)
		if err != nil {
			s.alertsError(w, r, err)
			return
		}
		f.RuleIDs = ids
	}
	list, total, err := s.Alerts.Alerts(r.Context(), f)
	if errors.Is(err, alerts.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": []alerts.Alert{}, "total": 0, "configured": false})
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if list == nil {
		list = []alerts.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": list, "total": total, "configured": true,
		"attack": s.alertsAttack(r.Context(), list)})
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

func alertID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return 0, false
	}
	return id, true
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	id, ok := alertID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	a, err := s.Alerts.Alert(ctx, id)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	evs, err := s.Alerts.AlertEvents(ctx, id, 50)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	act, err := s.Alerts.Activity(ctx, id)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	rel, err := s.Alerts.Related(ctx, a, 24*time.Hour, 20)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	resp := map[string]any{"alert": a, "events": nonNilSlice(evs), "activity": nonNilSlice(act), "related": nonNilSlice(rel),
		"attack": s.alertsAttack(ctx, append([]alerts.Alert{a}, rel...))}
	if s.Incidents != nil && current(r).perms.Has("incidents", "read") {
		if refs, err := s.Incidents.IncidentsForAlert(ctx, id); err == nil {
			resp["incidents"] = nonNilSlice(refs)
		}
	}
	if rule, err := s.Alerts.Rule(ctx, a.RuleID); err == nil {
		resp["rule"] = rule
		// Reguła z SigmaHQ: autor i źródło (licencja DRL 1.1).
		if at := rule.SigmaHQAttribution(); at != nil {
			resp["attribution"] = at
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// checkStatus sprawdza stan i powód (zamknięcie wymaga powodu).
func checkStatus(w http.ResponseWriter, status, reason, resolution string) bool {
	switch {
	case resolution != "" && (status != "closed" || !slices.Contains(risk.Resolutions, resolution)):
		writeError(w, http.StatusBadRequest, "bad_resolution", "rozstrzygnięcie (przy zamknięciu): true_positive, benign albo false_positive")
		return false
	case !slices.Contains(alertStatuses, status):
		writeError(w, http.StatusBadRequest, "bad_status", "status: open, acknowledged albo closed")
		return false
	case status == "closed" && (len([]rune(reason)) < 3 || len(reason) > 1000):
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód zamknięcia (np. fałszywy alarm, wyjaśnione, incydent)")
		return false
	case len(reason) > 1000:
		writeError(w, http.StatusBadRequest, "bad_reason", "komentarz do 1000 znaków")
		return false
	}
	return true
}

// setAlertStatus: wzięcie do analizy, zamknięcie z powodem albo ponowne
// otwarcie. Zmiana trafia na oś czasu alertu i do audytu.
func (s *Server) setAlertStatus(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := alertID(w, r)
	if !ok {
		return
	}
	var req struct {
		Status     string `json:"status"`
		Reason     string `json:"reason"`
		Resolution string `json:"resolution"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if !checkStatus(w, req.Status, req.Reason, req.Resolution) {
		return
	}
	upd, err := s.Alerts.SetStatus(r.Context(), id, req.Status, a.user.Username, req.Reason, req.Resolution, s.now())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "alert_status_changed", strconv.FormatInt(id, 10), map[string]any{
		"status": req.Status, "reason": req.Reason, "resolution": req.Resolution, "rule": upd.RuleID})
	writeJSON(w, http.StatusOK, map[string]any{"alert": upd})
}

// bulkAlertStatus: ten sam stan (i powód) dla wielu alertów naraz – np.
// zamknięcie serii fałszywych alarmów jednej reguły.
func (s *Server) bulkAlertStatus(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		IDs        []int64 `json:"ids"`
		Status     string  `json:"status"`
		Reason     string  `json:"reason"`
		Resolution string  `json:"resolution"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		writeError(w, http.StatusBadRequest, "bad_ids", "zaznacz od 1 do 500 alertów")
		return
	}
	if !checkStatus(w, req.Status, req.Reason, req.Resolution) {
		return
	}
	slices.Sort(req.IDs)
	req.IDs = slices.Compact(req.IDs)
	changed, err := s.Alerts.SetStatusMany(r.Context(), req.IDs, req.Status, a.user.Username, req.Reason, req.Resolution, s.now())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	ids := make([]int64, 0, len(changed))
	for _, c := range changed {
		ids = append(ids, c.ID)
	}
	s.audit(r, &a.user, "alert_status_changed_bulk", strconv.Itoa(len(ids))+" alertów", map[string]any{
		"status": req.Status, "reason": req.Reason, "resolution": req.Resolution, "ids": ids})
	writeJSON(w, http.StatusOK, map[string]any{"changed": len(changed), "ids": ids})
}

// assignAlert przypisuje alert analitykowi albo administratorowi (pusty login
// = bez przypisania).
func (s *Server) assignAlert(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := alertID(w, r)
	if !ok {
		return
	}
	var req struct {
		Assignee string `json:"assignee"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Assignee = strings.TrimSpace(req.Assignee)
	if req.Assignee != "" {
		users, err := s.assignees(r.Context())
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !slices.ContainsFunc(users, func(u assignee) bool { return u.Username == req.Assignee }) {
			writeError(w, http.StatusBadRequest, "bad_assignee", "alert można przypisać tylko aktywnemu analitykowi albo administratorowi")
			return
		}
	}
	upd, err := s.Alerts.Assign(r.Context(), id, req.Assignee, a.user.Username, s.now())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "alert_assigned", strconv.FormatInt(id, 10), map[string]any{"assignee": req.Assignee, "rule": upd.RuleID})
	writeJSON(w, http.StatusOK, map[string]any{"alert": upd})
}

// addAlertNote dopisuje notatkę do osi czasu alertu.
func (s *Server) addAlertNote(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := alertID(w, r)
	if !ok {
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" || len([]rune(req.Text)) > 4000 {
		writeError(w, http.StatusBadRequest, "bad_text", "notatka: od 1 do 4000 znaków")
		return
	}
	if err := s.Alerts.AddNote(r.Context(), id, a.user.Username, req.Text, s.now()); err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "alert_note_added", strconv.FormatInt(id, 10), nil)
	act, err := s.Alerts.Activity(r.Context(), id)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"activity": nonNilSlice(act)})
}

type assignee struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// assignees: aktywne konta, które mogą obsługiwać alerty.
func (s *Server) assignees(ctx context.Context) ([]assignee, error) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := []assignee{}
	for _, u := range users {
		if !u.Disabled && s.permsOf(ctx, u.Role).Has("alerts", "write") {
			out = append(out, assignee{Username: u.Username, DisplayName: u.DisplayName})
		}
	}
	return out, nil
}

func (s *Server) listAssignees(w http.ResponseWriter, r *http.Request) {
	users, err := s.assignees(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignees": users})
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
	// Reguły z SigmaHQ: autor i źródło (licencja DRL 1.1) – pokazywane w panelu.
	attributions := map[string]*alerts.Attribution{}
	for _, ru := range rules {
		if at := ru.SigmaHQAttribution(); at != nil {
			attributions[ru.ID] = at
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "errors": errs, "configured": true, "attributions": attributions})
}
