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
	"siem/internal/detect"
	"siem/panel/internal/events"
)

// Kreator korelacji (panel → Reguły detekcji → „Nowa korelacja”):
// przykładowe zdarzenia z polami i regułami, które do nich pasują
// (podpowiedź kroków i klucza), oraz zapis gotowej korelacji jako reguły
// panelu (gjallarhorn.panel_rules – detektor wczytuje ją obok plików).

// maxWizardEvents: najwięcej przykładowych zdarzeń w kreatorze.
const maxWizardEvents = 10

// maxPanelRuleSource: największa treść reguły z panelu.
const maxPanelRuleSource = 64 << 10

type wizardRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Title     string   `json:"title"`
	Level     string   `json:"level"`
	File      string   `json:"file"`
	Threshold bool     `json:"threshold"`
	Tags      []string `json:"tags"`
}

type wizardEvent struct {
	ID        string            `json:"event_id"`
	Timestamp time.Time         `json:"timestamp"`
	Dataset   string            `json:"dataset"`
	Host      string            `json:"host"`
	User      string            `json:"user"`
	Code      uint32            `json:"code"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields"`
	Product   string            `json:"product"`
	Service   string            `json:"service"`
	Rules     []wizardRule      `json:"rules"`
}

// knownRules zwraca wdrożone reguły zwykłe (bez korelacji i wbudowanych)
// oraz opisy wszystkich wdrożonych reguł; skip – pomija reguły z tego pliku
// (edytowana reguła panelu).
func (s *Server) knownRules(ctx context.Context, skip string) ([]*detect.Rule, []alerts.RuleInfo, error) {
	if s.Alerts == nil {
		return nil, nil, nil
	}
	infos, _, err := s.Alerts.Rules(ctx)
	if err != nil {
		return nil, nil, err
	}
	var known []*detect.Rule
	var live []alerts.RuleInfo
	for _, in := range infos {
		if in.RemovedAt != nil || (skip != "" && in.File == skip) {
			continue
		}
		live = append(live, in)
		if in.Source == "" || in.Mode == "correlation" {
			continue
		}
		if rule, err := detect.Parse([]byte(in.Source), in.File); err == nil {
			known = append(known, rule)
		}
	}
	return known, live, nil
}

// wizardEvents: przykładowe zdarzenia z polami i pasującymi regułami.
func (s *Server) wizardEvents(w http.ResponseWriter, r *http.Request) {
	if s.RuleTester == nil {
		writeError(w, http.StatusServiceUnavailable, "events_disabled", "wyszukiwarka zdarzeń wyłączona – kreator niedostępny")
		return
	}
	var req struct {
		Events []events.EventRef `json:"events"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Events) == 0 || len(req.Events) > maxWizardEvents {
		writeError(w, http.StatusBadRequest, "bad_events", "wybierz od 1 do 10 przykładowych zdarzeń")
		return
	}
	for _, e := range req.Events {
		if e.ID == "" || len(e.ID) > 256 || e.Timestamp.IsZero() {
			writeError(w, http.StatusBadRequest, "bad_events", "zdarzenie: identyfikator i czas")
			return
		}
	}
	known, _, err := s.knownRules(r.Context(), "")
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), SearchTimeout)
	defer cancel()
	evs, err := s.RuleTester.LoadEvents(ctx, req.Events)
	if err != nil {
		s.searchError(w, r, err)
		return
	}
	out := make([]wizardEvent, 0, len(evs))
	for i := range evs {
		e := &evs[i]
		de := detect.Event{Event: e}
		msg := e.Message
		if len([]rune(msg)) > 300 {
			msg = string([]rune(msg)[:299]) + "…"
		}
		we := wizardEvent{ID: e.ID, Timestamp: e.Timestamp, Dataset: e.Dataset, Host: e.HostName, User: e.UserName, Code: e.Code,
			Message: msg, Fields: de.Flat(), Rules: []wizardRule{}}
		we.Product, we.Service = detect.LogsourceFor(e.Dataset, e.Fields["winlog.channel"])
		for _, k := range known {
			if k.Match(de) {
				we.Rules = append(we.Rules, wizardRule{ID: k.ID, Name: k.Name, Title: k.Title, Level: k.Level, File: k.File,
					Threshold: k.IsThreshold(), Tags: nonNilSlice(k.Tags)})
			}
		}
		out = append(out, we)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "missing": len(req.Events) - len(out)})
}

func (s *Server) ruleAdminEnabled(w http.ResponseWriter) bool {
	if !s.alertsEnabled(w) {
		return false
	}
	if s.RuleAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, "rules_disabled", "zarządzanie regułami wyłączone w konfiguracji siem-api")
		return false
	}
	return true
}

func (s *Server) panelRuleError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, alerts.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiej reguły z panelu")
		return
	}
	s.alertsError(w, r, err)
}

func (s *Server) getPanelRule(w http.ResponseWriter, r *http.Request) {
	if !s.ruleAdminEnabled(w) {
		return
	}
	pr, err := s.RuleAdmin.PanelRule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.panelRuleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule": pr})
}

// savePanelRule zapisuje korelację z kreatora (z regułami bazowymi
// w tym samym tekście albo wdrożonymi). Detektor wczyta ją w ciągu 30 s.
func (s *Server) savePanelRule(w http.ResponseWriter, r *http.Request) {
	if !s.ruleAdminEnabled(w) {
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Source string `json:"source"`
		Note   string `json:"note"`
	}
	if !readJSONLimit(w, r, &req, 2*maxPanelRuleSource) {
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Source) > maxPanelRuleSource || len(req.Note) > 500 {
		writeError(w, http.StatusBadRequest, "too_long", "reguła najwyżej 64 KB, opis zmiany najwyżej 500 znaków")
		return
	}
	file := alerts.PanelRuleFile(id)
	known, live, err := s.knownRules(r.Context(), file)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	set, err := detect.ParseText([]byte(req.Source), file, known)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_rule", err.Error())
		return
	}
	if len(set.Correlations) != 1 || set.Correlations[0].ID != id {
		writeError(w, http.StatusBadRequest, "bad_rule", "reguła z panelu: jedna reguła korelacyjna o id "+id+
			" (reguły bazowe mogą być obok, rozdzielone ---)")
		return
	}
	// Id z tekstu nie mogą zajmować id reguł wdrożonych (z plików, wbudowanych
	// i innych reguł panelu) – detektor odrzuciłby duplikat.
	ids := []string{id}
	for _, rule := range set.Rules {
		if slices.Contains(ids, rule.ID) {
			writeError(w, http.StatusBadRequest, "duplicate_id", "id "+rule.ID+" powtórzone w tekście")
			return
		}
		ids = append(ids, rule.ID)
	}
	for _, in := range live {
		if slices.Contains(ids, in.ID) {
			writeError(w, http.StatusConflict, "duplicate_id", "id "+in.ID+" ma już reguła „"+in.Title+"” ("+in.File+")")
			return
		}
	}
	if err := s.RuleAdmin.SavePanelRule(r.Context(), id, req.Source, a.user.Username, s.now().UTC()); err != nil {
		s.alertsError(w, r, err)
		return
	}
	c := set.Correlations[0]
	s.audit(r, &a.user, "panel_rule_saved", id, map[string]any{"title": c.Title, "type": c.Type, "base_rules": len(c.Rules),
		"note": req.Note})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "file": file,
		"message": "zapisano – detektor wczyta regułę w ciągu 30 s"})
}

// deletePanelRule usuwa regułę z panelu. Osłabia detekcję jak wyłączenie:
// powód i ponowne podanie hasła.
func (s *Server) deletePanelRule(w http.ResponseWriter, r *http.Request) {
	if !s.ruleAdminEnabled(w) {
		return
	}
	a := current(r)
	id := r.PathValue("id")
	var req struct {
		Reason   string `json:"reason"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len([]rune(req.Reason)) < 3 || len(req.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód usunięcia reguły")
		return
	}
	pr, err := s.RuleAdmin.PanelRule(r.Context(), id)
	if err != nil {
		s.panelRuleError(w, r, err)
		return
	}
	if !s.reauth(w, r, req.Password, "panel_rule_delete") {
		return
	}
	if _, err := s.RuleAdmin.DeletePanelRule(r.Context(), id); err != nil {
		s.alertsError(w, r, err)
		return
	}
	s.audit(r, &a.user, "panel_rule_deleted", id, map[string]any{"reason": req.Reason, "created_by": pr.CreatedBy})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "usunięto – detektor przestanie oceniać regułę w ciągu 30 s"})
}
