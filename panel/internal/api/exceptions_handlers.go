// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/internal/lang"
)

// Wyjątki reguł (wersja 1.5.3): warunek (pole[|modyfikator] → wartość albo
// lista), przy którym reguła nie trafia – typowo powtarzalny fałszywy alarm.
// Wyjątek osłabia wykrywanie jak wyłączenie reguły: powód, ponowne podanie
// hasła i wpis w audycie; przed zapisem panel pokazuje, ile trafień z
// ostatnich 7 dni wyjątek by ukrył.

// ExceptionStore to wyjątki reguł (implementuje alerts.PG).
type ExceptionStore interface {
	ActiveExceptions(ctx context.Context, now time.Time) ([]alerts.RuleException, string, error)
	RuleExceptions(ctx context.Context, rule string) ([]alerts.RuleException, error)
	ExceptionCounts(ctx context.Context, now time.Time) (map[string]int, error)
	RuleException(ctx context.Context, id int64) (alerts.RuleException, error)
	AddRuleException(ctx context.Context, e alerts.RuleException) (int64, error)
	DeleteRuleException(ctx context.Context, id int64) (bool, error)
}

const (
	maxExceptionList   = 50  // najwięcej wartości na liście jednego pola
	maxExceptionValue  = 512 // najdłuższa wartość
	maxExceptionDays   = 365
	exceptionCheckDays = 7
)

// exceptionRule: reguła, do której można dodać wyjątek – wdrożona reguła
// Sigmy (także bazowa korelacji); bez korelacji i reguł wbudowanych.
func (s *Server) exceptionRule(w http.ResponseWriter, r *http.Request, id string) (*detect.Rule, alerts.RuleInfo, bool) {
	info, err := s.Alerts.Rule(r.Context(), id)
	if errors.Is(err, alerts.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiej reguły")
		return nil, info, false
	}
	if err != nil {
		s.alertsError(w, r, err)
		return nil, info, false
	}
	if info.RemovedAt != nil || info.Mode == "system" || info.Mode == "correlation" || info.Source == "" {
		writeError(w, http.StatusBadRequest, "no_exceptions", "wyjątki są dla wdrożonych reguł Sigmy (bez korelacji i reguł wbudowanych)")
		return nil, info, false
	}
	rule, err := detect.Parse([]byte(info.Source), info.File)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_rule", err)
		return nil, info, false
	}
	return rule, info, true
}

// validException sprawdza warunek wyjątku: wartości proste albo krótkie
// listy, potem kompilacja jak w detektorze (te same modyfikatory).
func validException(m map[string]any) error {
	simple := func(v any) bool {
		switch x := v.(type) {
		case string:
			return len(x) <= maxExceptionValue
		case float64, bool:
			return true
		}
		return false
	}
	for k, v := range m {
		if strings.TrimSpace(k) == "" || len(k) > 128 {
			return lang.Errorf("wyjątek: nieprawidłowa nazwa pola", "exception: invalid field name")
		}
		if l, ok := v.([]any); ok {
			if len(l) == 0 || len(l) > maxExceptionList {
				return lang.Errorf("wyjątek: lista %s – od 1 do %d wartości", "exception: list %s – 1 to %d values", k, maxExceptionList)
			}
			for _, x := range l {
				if !simple(x) {
					return lang.Errorf("wyjątek: nieprawidłowa wartość na liście %s", "exception: invalid value in list %s", k)
				}
			}
			continue
		}
		if !simple(v) {
			return lang.Errorf("wyjątek: nieprawidłowa wartość %s", "exception: invalid value of %s", k)
		}
	}
	_, err := detect.CompileException(m)
	return err
}

func (s *Server) exceptionsEnabled(w http.ResponseWriter) bool {
	if !s.alertsEnabled(w) {
		return false
	}
	if s.Exceptions == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

// listRuleExceptions: wyjątki reguły (także wygasłe).
func (s *Server) listRuleExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.exceptionsEnabled(w) {
		return
	}
	ex, err := s.Exceptions.RuleExceptions(r.Context(), r.PathValue("id"))
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exceptions": nonNilSlice(ex)})
}

// checkRuleException: ile trafień reguły z ostatnich 7 dni wyjątek by ukrył
// (z przykładami) – przed zapisem, bez zmian w detekcji.
func (s *Server) checkRuleException(w http.ResponseWriter, r *http.Request) {
	if !s.exceptionsEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Match map[string]any `json:"match"`
	}
	if !readJSONLimit(w, r, &req, 64<<10) {
		return
	}
	rule, _, ok := s.exceptionRule(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if err := validException(req.Match); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_exception", err)
		return
	}
	if s.RuleTester == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – sprawdzenie wyjątku niedostępne")
		return
	}
	sup, err := detect.Suppressed(rule, req.Match)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_exception", err)
		return
	}
	select {
	case ruleTestSlots <- struct{}{}:
		defer func() { <-ruleTestSlots }()
	default:
		writeError(w, http.StatusTooManyRequests, "busy", "trwają inne testy reguł – spróbuj za chwilę")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	to := s.now().UTC()
	res, err := s.RuleTester.TestRule(ctx, sup, to.Add(-exceptionCheckDays*24*time.Hour), to)
	s.audit(r, &a.user, "rule_exception_checked", rule.ID, map[string]any{"match": req.Match, "ok": err == nil})
	if err != nil {
		writeJSON(w, http.StatusOK, failed(lang.Errorf("wykonanie w ClickHouse nieudane: %w", "ClickHouse execution failed: %w", err)))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "days": exceptionCheckDays, "suppressed": res.Matched,
		"events": res.Events, "alerts": res.AlertsTotal, "sql": sup.SQL()})
}

// addRuleException zapisuje wyjątek: powód, opcjonalne wygaśnięcie (dni)
// i ponowne podanie hasła. Detektor wczyta go w ciągu 30 s.
func (s *Server) addRuleException(w http.ResponseWriter, r *http.Request) {
	if !s.exceptionsEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Match      map[string]any `json:"match"`
		Reason     string         `json:"reason"`
		Days       int            `json:"days"` // 0 – bez wygaśnięcia
		AIProposed bool           `json:"ai_proposed"`
		Password   string         `json:"password"`
	}
	if !readJSONLimit(w, r, &req, 64<<10) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	rule, info, ok := s.exceptionRule(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if err := validException(req.Match); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_exception", err)
		return
	}
	if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód wyjątku (np. kopia zapasowa uruchamiana co noc przez svc_backup)")
		return
	}
	if req.Days < 0 || req.Days > maxExceptionDays {
		writeError(w, http.StatusBadRequest, "bad_days", "wygaśnięcie: od 1 do 365 dni (0 – bez wygaśnięcia)")
		return
	}
	if !s.reauth(w, r, req.Password, "rule_exception_add") {
		return
	}
	now := s.now().UTC()
	e := alerts.RuleException{RuleID: rule.ID, Match: req.Match, Reason: req.Reason, CreatedBy: a.user.Username,
		CreatedAt: now, AIProposed: req.AIProposed}
	if req.Days > 0 {
		exp := now.Add(time.Duration(req.Days) * 24 * time.Hour)
		e.ExpiresAt = &exp
	}
	id, err := s.Exceptions.AddRuleException(r.Context(), e)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "rule_exception_added", rule.ID, map[string]any{"exception_id": id, "title": info.Title,
		"match": req.Match, "reason": req.Reason, "days": req.Days, "ai_proposed": req.AIProposed})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "message": "zapisano – detektor zastosuje wyjątek w ciągu 30 s"})
}

// deleteRuleException usuwa wyjątek – reguła znów wykrywa te zdarzenia
// (wzmocnienie detekcji, więc bez hasła; wpis w audycie).
func (s *Server) deleteRuleException(w http.ResponseWriter, r *http.Request) {
	if !s.exceptionsEnabled(w) {
		return
	}
	a := current(r)
	eid, err := strconv.ParseInt(r.PathValue("eid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "nieprawidłowe id wyjątku")
		return
	}
	e, err := s.Exceptions.RuleException(r.Context(), eid)
	if errors.Is(err, alerts.ErrNotFound) || (err == nil && e.RuleID != r.PathValue("id")) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego wyjątku")
		return
	}
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if _, err := s.Exceptions.DeleteRuleException(r.Context(), eid); err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "rule_exception_deleted", e.RuleID, map[string]any{"exception_id": eid, "match": e.Match,
		"reason": e.Reason, "created_by": e.CreatedBy})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "usunięto – reguła znów wykrywa te zdarzenia w ciągu 30 s"})
}

// ruleExceptions: obowiązujące wyjątki reguły do testu (te same co
// w detektorze); błąd odczytu – test bez wyjątków.
func (s *Server) ruleExceptions(ctx context.Context, rule string) []detect.Exception {
	if s.Exceptions == nil {
		return nil
	}
	all, _, err := s.Exceptions.ActiveExceptions(ctx, s.now().UTC())
	if err != nil {
		return nil
	}
	var out []detect.Exception
	for _, e := range all {
		if e.RuleID == rule {
			out = append(out, detect.Exception{ID: e.ID, RuleID: e.RuleID, Match: e.Match})
		}
	}
	return out
}
