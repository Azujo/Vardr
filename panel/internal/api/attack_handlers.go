package api

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/attack"
)

// MITRE ATT&CK w panelu: mapowanie alertów (z tagów reguł), filtr alertów
// po technice i taktyce, macierz pokrycia (reguły i alerty na technikę)
// i eksport warstwy dla ATT&CK Navigator.

// attackRef to technika albo taktyka w odpowiedziach API.
type attackRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// ruleAttack to ATT&CK reguły (przy alertach).
type ruleAttack struct {
	Techniques []attackRef `json:"techniques"`
	Tactics    []attackRef `json:"tactics"`
}

func toRuleAttack(d *attack.Dict, m attack.Mapping) ruleAttack {
	ra := ruleAttack{Techniques: []attackRef{}, Tactics: []attackRef{}}
	for _, t := range m.Techniques {
		ra.Techniques = append(ra.Techniques, attackRef{ID: t.ID, Name: t.Name, URL: t.URL()})
	}
	for _, s := range m.Tactics {
		if t, ok := d.Tactic(s); ok {
			ra.Tactics = append(ra.Tactics, attackRef{ID: t.ID, Name: t.Name,
				URL: "https://attack.mitre.org/tactics/" + t.ID + "/"})
		}
	}
	return ra
}

// ruleMappings zwraca reguły (także usunięte – alerty historyczne) z ich ATT&CK.
func (s *Server) ruleMappings(ctx context.Context) ([]alerts.RuleInfo, map[string]attack.Mapping, error) {
	infos, _, err := s.Alerts.Rules(ctx)
	if err != nil {
		return nil, nil, err
	}
	d := attack.Enterprise()
	out := make(map[string]attack.Mapping, len(infos))
	for _, in := range infos {
		out[in.ID] = d.Map(in.Tags)
	}
	return infos, out, nil
}

// alertsAttack: ATT&CK reguł podanych alertów (klucz – id reguły).
func (s *Server) alertsAttack(ctx context.Context, list []alerts.Alert) map[string]ruleAttack {
	out := map[string]ruleAttack{}
	if len(list) == 0 {
		return out
	}
	_, maps, err := s.ruleMappings(ctx)
	if err != nil {
		return out
	}
	d := attack.Enterprise()
	for _, a := range list {
		if _, done := out[a.RuleID]; done {
			continue
		}
		if m, ok := maps[a.RuleID]; ok && len(m.Techniques)+len(m.Tactics) > 0 {
			out[a.RuleID] = toRuleAttack(d, m)
		}
	}
	return out
}

// attackRuleFilter: reguły obejmujące technikę (T1110 obejmuje też
// podtechniki) albo taktykę (credential-access) – filtr listy alertów.
func (s *Server) attackRuleFilter(ctx context.Context, technique, tactic string) ([]string, error) {
	infos, maps, err := s.ruleMappings(ctx)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, in := range infos {
		m := maps[in.ID]
		if technique != "" && !attack.Covers(m, technique) {
			continue
		}
		if tactic != "" && !slices.Contains(m.Tactics, tactic) {
			continue
		}
		ids = append(ids, in.ID)
	}
	return ids, nil
}

// attackDictionary: słownik ATT&CK dla panelu (statyczny – długie buforowanie).
func (s *Server) attackDictionary(w http.ResponseWriter, _ *http.Request) {
	d := attack.Enterprise()
	w.Header().Set("Cache-Control", "private, max-age=86400")
	writeJSON(w, http.StatusOK, map[string]any{"version": d.Version, "tactics": d.Tactics, "techniques": d.Techniques})
}

type coverageRule struct {
	ID              string                `json:"id"`
	Title           string                `json:"title"`
	Level           string                `json:"level"`
	Mode            string                `json:"mode"`
	File            string                `json:"file"`
	Enabled         bool                  `json:"enabled"`
	CorrelationOnly bool                  `json:"correlation_only,omitempty"`
	Techniques      []string              `json:"techniques"`
	Alerts          alerts.RuleAlertCount `json:"alerts"`
	Warnings        []string              `json:"warnings,omitempty"`
}

// correlationOnlyPrefix: opis reguły bazowej korelacji (detektor, Infos).
const correlationOnlyPrefix = "Reguła bazowa korelacji – sama nie tworzy alertów"

// attackCoverage: reguły z technikami i liczbą alertów z ostatnich dni
// (macierz w panelu składa z tego kolory komórek).
func (s *Server) attackCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	days, err := attackDays(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_days", err.Error())
		return
	}
	rules, err := s.coverage(r.Context(), days)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": attack.Enterprise().Version, "days": days, "rules": rules})
}

func attackDays(r *http.Request) (int, error) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			return 0, fmt.Errorf("okres: od 1 do 365 dni")
		}
		days = n
	}
	return days, nil
}

func (s *Server) coverage(ctx context.Context, days int) ([]coverageRule, error) {
	infos, maps, err := s.ruleMappings(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := s.Alerts.AlertCountsByRule(ctx, s.now().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		return nil, err
	}
	out := []coverageRule{}
	for _, in := range infos {
		if in.RemovedAt != nil {
			continue
		}
		m := maps[in.ID]
		cr := coverageRule{ID: in.ID, Title: in.Title, Level: in.Level, Mode: in.Mode, File: in.File, Enabled: in.Enabled,
			CorrelationOnly: strings.HasPrefix(in.Description, correlationOnlyPrefix), Techniques: []string{},
			Alerts: counts[in.ID], Warnings: m.Warnings}
		for _, t := range m.Techniques {
			cr.Techniques = append(cr.Techniques, t.ID)
		}
		out = append(out, cr)
	}
	return out, nil
}

// attackNavigator: warstwa ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
// – techniki pokryte włączonymi regułami (wynik = liczba alertów w okresie).
func (s *Server) attackNavigator(w http.ResponseWriter, r *http.Request) {
	if !s.alertsEnabled(w) {
		return
	}
	days, err := attackDays(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_days", err.Error())
		return
	}
	rules, err := s.coverage(r.Context(), days)
	if err != nil {
		s.alertsError(w, r, err)
		return
	}
	d := attack.Enterprise()
	type tech struct {
		rules  []string
		alerts int
	}
	byTech := map[string]*tech{}
	for _, cr := range rules {
		if !cr.Enabled || cr.CorrelationOnly {
			continue
		}
		for _, id := range cr.Techniques {
			t := byTech[id]
			if t == nil {
				t = &tech{}
				byTech[id] = t
			}
			t.rules = append(t.rules, cr.Title)
			t.alerts += cr.Alerts.Total
		}
	}
	type navTech struct {
		TechniqueID string `json:"techniqueID"`
		Tactic      string `json:"tactic,omitempty"`
		Score       int    `json:"score"`
		Comment     string `json:"comment"`
		Enabled     bool   `json:"enabled"`
	}
	var techs []navTech
	maxScore := 1
	for _, id := range slices.Sorted(maps.Keys(byTech)) {
		t := byTech[id]
		info, _ := d.Technique(id)
		for _, ta := range info.Tactics {
			techs = append(techs, navTech{TechniqueID: id, Tactic: ta, Score: t.alerts, Enabled: true,
				Comment: fmt.Sprintf("Reguły Vardra: %s. Alerty z %d dni: %d.", strings.Join(t.rules, "; "), days, t.alerts)})
		}
		maxScore = max(maxScore, t.alerts)
	}
	version := d.Version
	if i := strings.IndexByte(version, '.'); i > 0 {
		version = version[:i]
	}
	layer := map[string]any{
		"name":        "Vardr – pokrycie reguł",
		"description": fmt.Sprintf("Techniki pokryte włączonymi regułami Vardra; wynik = liczba alertów z %d dni (%s).", days, s.now().UTC().Format("2006-01-02")),
		"domain":      "enterprise-attack",
		"versions":    map[string]string{"attack": version, "navigator": "5.1.0", "layer": "4.5"},
		"techniques":  techs,
		"gradient":    map[string]any{"colors": []string{"#c8e6c9", "#e65100"}, "minValue": 0, "maxValue": maxScore},
		"legendItems": []map[string]string{{"label": "pokryte, bez alertów", "color": "#c8e6c9"},
			{"label": "najwięcej alertów", "color": "#e65100"}},
		"showTacticRowBackground": true,
		"hideDisabled":            false,
	}
	b, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vardr-attack-%s.json"`, s.now().UTC().Format("20060102")))
	_, _ = w.Write(b)
}
