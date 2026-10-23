// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/attack"
	"siem/internal/detect"
	"siem/internal/lang"
	"siem/internal/model"
	"siem/panel/internal/events"
)

// RuleTester wykonuje regułę na zdarzeniach w ClickHouse (implementuje events.Searcher).
type RuleTester interface {
	TestRule(ctx context.Context, r *detect.Rule, from, to time.Time) (events.RuleTestResult, error)
	TestCorrelation(ctx context.Context, c *detect.Correlation, from, to time.Time) (events.RuleTestResult, error)
	LoadEvents(ctx context.Context, refs []events.EventRef) ([]model.Event, error)
}

// RuleAdmin to wersje i ustawienia reguł (implementuje alerts.PG).
type RuleAdmin interface {
	RuleVersions(ctx context.Context, rule string) ([]alerts.RuleVersion, error)
	SetOverride(ctx context.Context, rule string, o alerts.Override) error
	ClearOverride(ctx context.Context, rule string) (bool, error)
	TrialStats(ctx context.Context) ([]alerts.TrialStat, error)
	PanelRule(ctx context.Context, id string) (alerts.PanelRule, error)
	SavePanelRule(ctx context.Context, id, source, by string, now time.Time) error
	DeletePanelRule(ctx context.Context, id string) (bool, error)
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
	if strings.Contains(req.Source, "correlation:") {
		s.testCorrelation(w, r, req.Source, req.Hours)
		return
	}
	rule, err := detect.Parse([]byte(req.Source), "test.yml")
	if err != nil {
		writeJSON(w, http.StatusOK, failed(err))
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
		writeJSON(w, http.StatusOK, failed(lang.Errorf("wykonanie w ClickHouse nieudane: %w", "ClickHouse execution failed: %w", err)))
		return
	}
	var th *alerts.Threshold
	if t := rule.Vardr.Threshold; t != nil {
		th = &alerts.Threshold{Count: t.Count, WindowS: int(time.Duration(t.Window) / time.Second), Distinct: t.Distinct}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res, "sql": rule.SQL(),
		"attack_warnings":    nonNilSlice(attack.Enterprise().Map(rule.Tags).Warnings),
		"attack_warnings_en": nonNilSlice(attack.Enterprise().Map(rule.Tags).WarningsEn),
		"rule": map[string]any{"id": rule.ID, "title": rule.Title, "level": rule.Level, "group_by": rule.Vardr.GroupBy,
			"suppress_s": int(time.Duration(rule.Vardr.Suppress) / time.Second), "threshold": th, "mode": rule.Vardr.Mode}})
}

// testCorrelation: test reguły korelacyjnej (z regułami bazowymi w tym
// samym tekście albo wdrożonymi) na zdarzeniach z ostatnich godzin.
func (s *Server) testCorrelation(w http.ResponseWriter, r *http.Request, source string, hours int) {
	a := current(r)
	if s.RuleTester == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – test reguły niedostępny")
		return
	}
	// Reguły wdrożone – bazowe dla korelacji, której reguły nie ma w tekście.
	known, _, err := s.knownRules(r.Context(), "")
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	set, err := detect.ParseText([]byte(source), "test.yml", known)
	if err != nil {
		writeJSON(w, http.StatusOK, failed(err))
		return
	}
	if len(set.Correlations) != 1 {
		writeJSON(w, http.StatusOK, failed(lang.Errorf("test: jedna reguła korelacyjna (reguły bazowe mogą być obok, rozdzielone ---)", "test: one correlation rule (base rules may be next to it, separated by ---)")))
		return
	}
	c := set.Correlations[0]
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
	res, err := s.RuleTester.TestCorrelation(ctx, c, to.Add(-time.Duration(hours)*time.Hour), to)
	s.audit(r, &a.user, "rule_tested", c.ID, map[string]any{"title": c.Title, "hours": hours, "ok": err == nil, "correlation": true})
	if err != nil {
		writeJSON(w, http.StatusOK, failed(lang.Errorf("wykonanie w ClickHouse nieudane: %w", "ClickHouse execution failed: %w", err)))
		return
	}
	var base []string
	for _, b := range c.Rules {
		base = append(base, b.Title+" ("+b.ID+")")
	}
	var warns, warnsEn []string
	for _, tags := range append(tagsOf(set.Rules), c.Tags) {
		m := attack.Enterprise().Map(tags)
		warns, warnsEn = append(warns, m.Warnings...), append(warnsEn, m.WarningsEn...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res, "sql": c.EventsSQL("siem.events", to.Add(-time.Duration(hours)*time.Hour), to, 20000),
		"attack_warnings": nonNilSlice(warns), "attack_warnings_en": nonNilSlice(warnsEn),
		"rule": map[string]any{"id": c.ID, "title": c.Title, "level": c.Level, "group_by": c.GroupBy, "mode": "correlation",
			"suppress_s": int(time.Duration(c.Vardr.Suppress) / time.Second), "correlation": map[string]any{"type": c.Type,
				"timespan_s": int(c.Timespan / time.Second), "count": c.Count, "field": c.Field, "rules": base}}})
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

// setRuleEnabled włącza albo wyłącza regułę z panelu (ponad plik), ustawia
// tryb próbny (trial – trafienia liczone bez alertów) albo przywraca
// ustawienie z pliku (enabled = null). Wyłączenie (także przejście włączonej
// reguły w próbę) osłabia detekcję: wymaga powodu i ponownego podania hasła;
// detektor stosuje zmianę w 30 s.
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
		Trial    bool   `json:"trial"`
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
	if req.Trial && !trialCapable(rule) {
		writeError(w, http.StatusBadRequest, "no_trial", "tryb próbny jest dla reguł Sigmy (bez korelacji i reguł wbudowanych)")
		return
	}
	if req.Trial {
		f := false
		req.Enabled = &f
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
		err = s.RuleAdmin.SetOverride(r.Context(), id, alerts.Override{Enabled: *req.Enabled, Trial: req.Trial, Reason: req.Reason,
			ChangedBy: a.user.Username, ChangedAt: s.now()})
	}
	if errors.Is(err, alerts.ErrNotConfigured) || err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "rule_enabled_changed", id, map[string]any{"title": rule.Title, "enabled": after, "trial": req.Trial,
		"from_file": req.Enabled == nil, "reason": req.Reason, "previous": rule.Enabled})
	msg := "zmiana zacznie działać w ciągu 30 s (przeładowanie reguł w detektorze)"
	if req.Trial {
		msg = "tryb próbny zacznie działać w ciągu 30 s – trafienia bez alertów w „Próbach reguł”"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": after, "trial": req.Trial, "message": msg})
}

// trialCapable: tryb próbny dla reguł Sigmy ocenianych przez detektor
// (bez korelacji, reguł wbudowanych i reguł bazowych korelacji).
func trialCapable(r alerts.RuleInfo) bool {
	return r.RemovedAt == nil && r.Mode != "system" && r.Mode != "correlation" &&
		!strings.HasPrefix(r.Description, correlationOnlyPrefix)
}

// maxBulkRules: najwięcej reguł w jednej zmianie zbiorczej.
const maxBulkRules = 5000

// bulkRules zmienia wiele reguł naraz: włączenie, wyłączenie, tryb próbny
// albo powrót do ustawienia z pliku. Zawsze z powodem i ponownym podaniem
// hasła – hurtowe włączenie może zalać analityków alertami, a wyłączenie
// osłabia detekcję. Reguł, których zmiana nie dotyczy, nie rusza.
func (s *Server) bulkRules(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	if s.RuleAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return
	}
	a := current(r)
	var req struct {
		IDs      []string `json:"ids"`
		Action   string   `json:"action"` // enable | disable | trial | file
		Reason   string   `json:"reason"`
		Password string   `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case req.Action != "enable" && req.Action != "disable" && req.Action != "trial" && req.Action != "file":
		writeError(w, http.StatusBadRequest, "bad_action", "action: enable, disable, trial albo file")
		return
	case len(req.IDs) == 0 || len(req.IDs) > maxBulkRules:
		writeError(w, http.StatusBadRequest, "bad_ids", "zaznacz od 1 do 5000 reguł")
		return
	case len([]rune(req.Reason)) < 3 || len(req.Reason) > 500:
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód zmiany (trafi do audytu)")
		return
	}
	if !s.reauth(w, r, req.Password, "rules_bulk") {
		return
	}
	rules, _, err := s.Alerts.Rules(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	byID := make(map[string]alerts.RuleInfo, len(rules))
	for _, ru := range rules {
		byID[ru.ID] = ru
	}
	now := s.now()
	var changed []string
	skipped := 0
	for _, id := range req.IDs {
		ru, ok := byID[id]
		if !ok || ru.RemovedAt != nil || ru.Mode == "system" || (req.Action == "trial" && !trialCapable(ru)) {
			skipped++
			continue
		}
		cur := "file"
		if o := ru.Override; o != nil {
			cur = map[bool]string{true: "enable", false: "disable"}[o.Enabled]
			if o.Trial {
				cur = "trial"
			}
		}
		if cur == req.Action {
			skipped++
			continue
		}
		if req.Action == "file" {
			_, err = s.RuleAdmin.ClearOverride(r.Context(), id)
		} else {
			err = s.RuleAdmin.SetOverride(r.Context(), id, alerts.Override{Enabled: req.Action == "enable", Trial: req.Action == "trial",
				Reason: req.Reason, ChangedBy: a.user.Username, ChangedAt: now})
		}
		if err != nil {
			break
		}
		changed = append(changed, id)
	}
	sample := changed
	if len(sample) > 100 {
		sample = sample[:100]
	}
	s.audit(r, &a.user, "rules_bulk_changed", req.Action, map[string]any{"action": req.Action, "changed": len(changed),
		"skipped": skipped, "reason": req.Reason, "rules": sample, "ok": err == nil})
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changed": len(changed), "skipped": skipped,
		"message": fmt.Sprintf("zmienione reguły: %d (bez zmian: %d) – detektor zastosuje zmiany w ciągu 30 s", len(changed), skipped)})
}

// trialRules: wyniki reguł w trybie próbnym (trafienia bez alertów).
func (s *Server) trialRules(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	if s.RuleAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return
	}
	stats, err := s.RuleAdmin.TrialStats(r.Context())
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"trials": nonNilSlice(stats), "now": s.now().UTC()})
}

func tagsOf(rules []*detect.Rule) [][]string {
	out := make([][]string, 0, len(rules)+1)
	for _, r := range rules {
		out = append(out, r.Tags)
	}
	return out
}
