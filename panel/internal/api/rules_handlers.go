package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/panel/internal/events"
)

// RuleTester wykonuje regułę na zdarzeniach w ClickHouse (implementuje events.Searcher).
type RuleTester interface {
	TestRule(ctx context.Context, r *detect.Rule, from, to time.Time) (events.RuleTestResult, error)
}

// RuleAdmin to wersje i ustawienia reguł (implementuje alerts.PG).
type RuleAdmin interface {
	RuleVersions(ctx context.Context, rule string) ([]alerts.RuleVersion, error)
	SetOverride(ctx context.Context, rule string, o alerts.Override) error
	ClearOverride(ctx context.Context, rule string) (bool, error)
}

// ruleTestSlots: najwyżej dwa testy reguł naraz (każdy to pełne zapytanie do
// ClickHouse, nawet za 7 dni – bez limitu panel mógłby zagłodzić bazę).
var ruleTestSlots = make(chan struct{}, 2)

// testRule sprawdza i wykonuje regułę (YAML) na zdarzeniach z ostatnich
// godzin – bez wdrażania. Pokazuje dopasowania i alerty, które by powstały.
func (s *Server) testRule(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	var req struct {
		Source string `json:"source"`
		Hours  int    `json:"hours"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Hours < 1 || req.Hours > 168 {
		writeError(w, http.StatusBadRequest, "bad_hours", "okres testu: od 1 do 168 godzin")
		return
	}
	rule, err := detect.Parse([]byte(req.Source), "test.yml")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if s.RuleTester == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – test reguły niedostępny")
		return
	}
	select {
	case ruleTestSlots <- struct{}{}:
		defer func() { <-ruleTestSlots }()
	default:
		writeError(w, http.StatusTooManyRequests, "busy", "trwają inne testy reguł – spróbuj za chwilę")
		return
	}
	// Ten sam limit co wyszukiwarka – sterownik zamienia go na max_execution_time,
	// który konto siem_panel ogranicza do 30 s.
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	to := s.now().UTC()
	res, err := s.RuleTester.TestRule(ctx, rule, to.Add(-time.Duration(req.Hours)*time.Hour), to)
	s.audit(r, &a.user, "rule_tested", rule.ID, map[string]any{"title": rule.Title, "hours": req.Hours, "ok": err == nil})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "wykonanie w ClickHouse nieudane: " + err.Error()})
		return
	}
	var th *alerts.Threshold
	if t := rule.Heimdall.Threshold; t != nil {
		th = &alerts.Threshold{Count: t.Count, WindowS: int(time.Duration(t.Window) / time.Second), Distinct: t.Distinct}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res, "sql": rule.SQL(),
		"rule": map[string]any{"id": rule.ID, "title": rule.Title, "level": rule.Level, "group_by": rule.Heimdall.GroupBy,
			"suppress_s": int(time.Duration(rule.Heimdall.Suppress) / time.Second), "threshold": th, "mode": rule.Heimdall.Mode}})
}

func (s *Server) ruleVersions(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	if s.RuleAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return
	}
	vs, err := s.RuleAdmin.RuleVersions(r.Context(), r.PathValue("id"))
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": nonNilSlice(vs)})
}

// setRuleEnabled włącza albo wyłącza regułę z panelu (ponad plik) albo
// przywraca ustawienie z pliku (enabled = null). Wyłączenie osłabia detekcję:
// wymaga powodu i ponownego podania hasła; detektor stosuje zmianę w 30 s.
func (s *Server) setRuleEnabled(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	if s.RuleAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Enabled  *bool  `json:"enabled"`
		Reason   string `json:"reason"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	rule, err := s.Alerts.Rule(r.Context(), id)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	if rule.RemovedAt != nil || rule.Mode == "system" {
		writeError(w, http.StatusBadRequest, "not_switchable", "tej reguły nie można przełączać z panelu")
		return
	}
	after := rule.FileEnabled
	if req.Enabled != nil {
		after = *req.Enabled
	}
	if rule.Enabled && !after {
		if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
			writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód wyłączenia reguły (np. fałszywe alarmy do czasu poprawki)")
			return
		}
		if !s.reauth(w, r, req.Password, "rule_disable") {
			return
		}
	}
	if req.Enabled == nil {
		_, err = s.RuleAdmin.ClearOverride(r.Context(), id)
	} else {
		err = s.RuleAdmin.SetOverride(r.Context(), id, alerts.Override{Enabled: *req.Enabled, Reason: req.Reason,
			ChangedBy: a.user.Username, ChangedAt: s.now()})
	}
	if errors.Is(err, alerts.ErrNotConfigured) || err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "rule_enabled_changed", id, map[string]any{"title": rule.Title, "enabled": after,
		"from_file": req.Enabled == nil, "reason": req.Reason, "previous": rule.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{"enabled": after, "message": "zmiana zacznie działać w ciągu 30 s (przeładowanie reguł w detektorze)"})
}
