// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/lang"
	"siem/panel/internal/api/store"
	"siem/panel/internal/notify"
	"siem/panel/internal/syslang"
)

// IncidentStore to incydenty (implementuje store.PG).
type IncidentStore interface {
	CreateIncident(ctx context.Context, x store.Incident, alerts []store.IncidentAlert, now time.Time) (store.Incident, error)
	Incident(ctx context.Context, id int64) (store.Incident, error)
	Incidents(ctx context.Context, scope string) ([]store.Incident, error)
	UpdateIncident(ctx context.Context, x store.Incident, activity []store.IncidentActivity, now time.Time) (store.Incident, error)
	AddIncidentActivity(ctx context.Context, id int64, activity []store.IncidentActivity, now time.Time) error
	AddIncidentEvidence(ctx context.Context, id int64, activity store.IncidentActivity) error
	AddIncidentAlerts(ctx context.Context, id int64, alerts []store.IncidentAlert, activity store.IncidentActivity) error
	RemoveIncidentAlert(ctx context.Context, id, alertID int64, activity store.IncidentActivity) error
	IncidentAlerts(ctx context.Context, id int64) ([]store.IncidentAlert, error)
	IncidentActivityLog(ctx context.Context, id int64) ([]store.IncidentActivity, error)
	IncidentReports(ctx context.Context, id int64) ([]store.IncidentReport, error)
	SaveIncidentReport(ctx context.Context, id int64, kind, content, by string, now time.Time) error
	SubmitIncidentReport(ctx context.Context, id int64, kind, content, reference, by string, at, now time.Time) error
	IncidentsForAlert(ctx context.Context, alertID int64) ([]store.IncidentRef, error)
	ReminderSent(ctx context.Context, id int64, deadline, stage string, now time.Time) (bool, error)
}

var (
	incidentSeverities = []string{"low", "medium", "high", "critical"}
	triState           = []string{"yes", "no", "unknown"}
	reportKinds        = []string{"early_warning", "notification", "intermediate", "final"}
	statusLabels       = map[string]string{"open": "otwarty", "investigating": "analiza", "contained": "opanowany",
		"resolved": "rozwiązany", "closed": "zamknięty"}
	severityLabels = map[string]string{"low": "niska", "medium": "średnia", "high": "wysoka", "critical": "krytyczna"}
	reportLabels   = map[string]string{"early_warning": "wczesne ostrzeżenie", "notification": "zgłoszenie incydentu",
		"intermediate": "sprawozdanie pośrednie", "final": "sprawozdanie końcowe"}
)

// statusTransitions: dozwolone zmiany statusu. Praca może wracać (np. z
// analizy do otwartych, z rozwiązanych do opanowanych), ale zamknięcie jest
// ostateczne – zamknięty incydent jest tylko do odczytu (także w bazie).
var statusTransitions = map[string][]string{
	"open":          {"investigating", "contained", "resolved"},
	"investigating": {"open", "contained", "resolved"},
	"contained":     {"investigating", "resolved"},
	"resolved":      {"investigating", "contained", "closed"},
	"closed":        {},
}

// Deadline to termin zgłoszenia NIS2 (art. 23 dyrektywy 2022/2555).
type Deadline struct {
	Kind        string     `json:"kind"`
	Label       string     `json:"label"`
	Due         time.Time  `json:"due"`
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
}

// deadlines: wczesne ostrzeżenie – 24 h od stwierdzenia; zgłoszenie – 72 h;
// sprawozdanie końcowe – miesiąc od zgłoszenia (przed jego wysłaniem – od
// terminu zgłoszenia). Tylko incydent poważny z chwilą stwierdzenia.
func deadlines(x store.Incident, reports []store.IncidentReport) []Deadline {
	if !x.Significant || x.AwareAt == nil {
		return []Deadline{}
	}
	sub := map[string]*time.Time{}
	for _, r := range reports {
		sub[r.Kind] = r.SubmittedAt
	}
	aware := x.AwareAt.UTC()
	notifBase := aware.Add(72 * time.Hour)
	if t := sub["notification"]; t != nil {
		notifBase = t.UTC()
	}
	return []Deadline{
		{Kind: "early_warning", Label: reportLabels["early_warning"], Due: aware.Add(24 * time.Hour), SubmittedAt: sub["early_warning"]},
		{Kind: "notification", Label: reportLabels["notification"], Due: aware.Add(72 * time.Hour), SubmittedAt: sub["notification"]},
		{Kind: "final", Label: reportLabels["final"], Due: notifBase.AddDate(0, 1, 0), SubmittedAt: sub["final"]},
	}
}

func (s *Server) incidentsEnabled(w http.ResponseWriter) bool {
	if s.Incidents == nil {
		writeError(w, http.StatusServiceUnavailable, "incidents_disabled", "incydenty niedostępne w tej konfiguracji")
		return false
	}
	return true
}

func incidentID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny numer incydentu")
		return 0, false
	}
	return id, true
}

func (s *Server) incidentError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego incydentu")
	case errors.Is(err, store.ErrSubmitted):
		writeError(w, http.StatusConflict, "submitted", "zgłoszenie zostało już wysłane – jego treść jest zamrożona")
	case errors.Is(err, store.ErrClosed):
		writeError(w, http.StatusConflict, "closed", "incydent jest zamknięty – tylko do odczytu")
	default:
		s.internalError(w, r, err)
	}
}

// snapshot: migawki alertów (Gjallarhorn) do incydentu.
func (s *Server) snapshot(ctx context.Context, ids []int64, by string, now time.Time) ([]store.IncidentAlert, error) {
	if len(ids) > 500 {
		return nil, lang.Errorf("najwyżej 500 alertów naraz", "at most 500 alerts at once")
	}
	if len(ids) > 0 && s.Alerts == nil {
		return nil, errors.New("alerts module disabled")
	}
	out := make([]store.IncidentAlert, 0, len(ids))
	for _, id := range ids {
		a, err := s.Alerts.Alert(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("alert %d: %w", id, err)
		}
		out = append(out, alertSnapshot(a, by, now))
	}
	return out, nil
}

func alertSnapshot(a alerts.Alert, by string, now time.Time) store.IncidentAlert {
	return store.IncidentAlert{AlertID: a.ID, RuleID: a.RuleID, RuleTitle: a.RuleTitle, Level: a.Level, HostName: a.HostName,
		AgentID: a.AgentID, UserName: a.UserName, Summary: a.Summary, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, AddedBy: by, AddedAt: now}
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	list, err := s.Incidents.Incidents(r.Context(), r.URL.Query().Get("scope"))
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	type row struct {
		store.Incident
		Deadlines []Deadline `json:"deadlines"`
	}
	out := make([]row, 0, len(list))
	for _, x := range list {
		var reps []store.IncidentReport
		if x.Significant {
			if reps, err = s.Incidents.IncidentReports(r.Context(), x.ID); err != nil {
				s.incidentError(w, r, err)
				return
			}
		}
		out = append(out, row{x, deadlines(x, reps)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": out, "now": s.now().UTC()})
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	var req struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Severity    string  `json:"severity"`
		AlertIDs    []int64 `json:"alert_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	switch {
	case len([]rune(req.Title)) < 3 || len([]rune(req.Title)) > 200:
		writeError(w, http.StatusBadRequest, "bad_title", "tytuł incydentu: 3–200 znaków")
		return
	case !slices.Contains(incidentSeverities, req.Severity):
		writeError(w, http.StatusBadRequest, "bad_severity", "waga: low, medium, high albo critical")
		return
	case len(req.Description) > 10000:
		writeError(w, http.StatusBadRequest, "bad_description", "opis jest za długi")
		return
	}
	now := s.now()
	snaps, err := s.snapshot(r.Context(), req.AlertIDs, a.user.Username, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_alerts", err)
		return
	}
	x, err := s.Incidents.CreateIncident(r.Context(), store.Incident{Title: req.Title, Description: req.Description,
		Severity: req.Severity, Assignee: a.user.Username, CreatedBy: a.user.Username}, snaps, now)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	s.audit(r, &a.user, "incident_created", strconv.FormatInt(x.ID, 10), map[string]any{"title": x.Title, "alerts": len(snaps)})
	writeJSON(w, http.StatusCreated, map[string]any{"incident": x})
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	x, err := s.Incidents.Incident(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	als, err := s.Incidents.IncidentAlerts(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	act, err := s.Incidents.IncidentActivityLog(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	reps, err := s.Incidents.IncidentReports(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": x, "alerts": nonNilSlice(als), "activity": nonNilSlice(act),
		"reports": nonNilSlice(reps), "deadlines": deadlines(x, reps), "now": s.now().UTC()})
}

// updateIncident: zmiana pól incydentu; każda zmiana to wpis osi czasu,
// zmiana chwili stwierdzenia i oznaczenia „poważny” – także w audycie.
func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	var req struct {
		Title       *string    `json:"title"`
		Description *string    `json:"description"`
		Severity    *string    `json:"severity"`
		Status      *string    `json:"status"`
		Comment     string     `json:"comment"` // zmiana statusu: komentarz (przy zamknięciu – wymagane podsumowanie)
		Assignee    *string    `json:"assignee"`
		Significant *bool      `json:"significant"`
		AwareAt     *time.Time `json:"aware_at"`
		Malicious   *string    `json:"malicious"`
		CrossBorder *string    `json:"cross_border"`
		Impact      *string    `json:"impact"`
		RootCause   *string    `json:"root_cause"`
		Mitigation  *string    `json:"mitigation"`
		IOCs        *string    `json:"iocs"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	prev, err := s.Incidents.Incident(r.Context(), id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	if prev.Status == "closed" {
		s.incidentError(w, r, store.ErrClosed)
		return
	}
	now := s.now()
	x := prev
	var act []store.IncidentActivity
	change := func(field, from, to string) {
		act = append(act, store.IncidentActivity{At: now, Username: a.user.Username, Kind: "field",
			Text: field, Details: map[string]any{"field": field, "from": from, "to": to}})
	}
	text := func(dst *string, v *string, field string, max int) bool {
		if v == nil || *v == *dst {
			return true
		}
		if len(*v) > max {
			writeError(w, http.StatusBadRequest, "too_long", field+": za długie")
			return false
		}
		change(field, *dst, *v)
		*dst = *v
		return true
	}
	enum := func(dst *string, v *string, allowed []string, field string) bool {
		if v == nil || *v == *dst {
			return true
		}
		if !slices.Contains(allowed, *v) {
			writeError(w, http.StatusBadRequest, "bad_"+field, field+": niedozwolona wartość")
			return false
		}
		change(field, *dst, *v)
		*dst = *v
		return true
	}
	if req.Title != nil {
		t := strings.TrimSpace(*req.Title)
		if len([]rune(t)) < 3 || len([]rune(t)) > 200 {
			writeError(w, http.StatusBadRequest, "bad_title", "tytuł incydentu: 3–200 znaków")
			return
		}
		req.Title = &t
	}
	if !text(&x.Title, req.Title, "title", 800) || !text(&x.Description, req.Description, "description", 10000) ||
		!text(&x.Assignee, req.Assignee, "assignee", 64) || !text(&x.Impact, req.Impact, "impact", 10000) ||
		!text(&x.RootCause, req.RootCause, "root_cause", 10000) || !text(&x.Mitigation, req.Mitigation, "mitigation", 10000) ||
		!text(&x.IOCs, req.IOCs, "iocs", 20000) || !enum(&x.Severity, req.Severity, incidentSeverities, "severity") ||
		!enum(&x.Malicious, req.Malicious, triState, "malicious") ||
		!enum(&x.CrossBorder, req.CrossBorder, triState, "cross_border") {
		return
	}
	if req.Status != nil && *req.Status != x.Status {
		to := *req.Status
		if !slices.Contains(statusTransitions[x.Status], to) {
			writeError(w, http.StatusBadRequest, "bad_transition", fmt.Sprintf("nie można zmienić statusu z „%s” na „%s”",
				statusLabels[x.Status], statusLabels[to]))
			return
		}
		comment := strings.TrimSpace(req.Comment)
		if len(comment) > 10000 {
			writeError(w, http.StatusBadRequest, "too_long", "komentarz jest za długi")
			return
		}
		if to == "closed" {
			if len([]rune(comment)) < 10 {
				writeError(w, http.StatusBadRequest, "close_summary", "zamknięcie wymaga podsumowania (co najmniej 10 znaków)")
				return
			}
			// Incydent poważny: najpierw sprawozdanie końcowe (art. 23 NIS2).
			if x.Significant || (req.Significant != nil && *req.Significant) {
				reps, err := s.Incidents.IncidentReports(r.Context(), id)
				if err != nil {
					s.incidentError(w, r, err)
					return
				}
				final := false
				for _, rp := range reps {
					final = final || (rp.Kind == "final" && rp.SubmittedAt != nil)
				}
				if !final {
					writeError(w, http.StatusConflict, "final_report_missing",
						"incydent poważny (NIS2) można zamknąć po oznaczeniu sprawozdania końcowego jako wysłanego")
					return
				}
			}
		}
		change("status", x.Status, to)
		if comment != "" {
			act = append(act, store.IncidentActivity{At: now, Username: a.user.Username, Kind: "note", Text: comment,
				Details: map[string]any{"status": to}})
		}
		x.Status = to
	}
	nis2 := map[string]any{}
	if req.Significant != nil && *req.Significant != x.Significant {
		change("significant", strconv.FormatBool(x.Significant), strconv.FormatBool(*req.Significant))
		x.Significant = *req.Significant
		nis2["significant"] = x.Significant
		// Oznaczenie jako poważny bez podanej chwili stwierdzenia – teraz.
		if x.Significant && x.AwareAt == nil && req.AwareAt == nil {
			t := now.UTC().Truncate(time.Minute)
			req.AwareAt = &t
		}
	}
	if req.AwareAt != nil && (x.AwareAt == nil || !req.AwareAt.Equal(*x.AwareAt)) {
		if req.AwareAt.After(now.Add(5 * time.Minute)) {
			writeError(w, http.StatusBadRequest, "bad_aware_at", "chwila stwierdzenia incydentu nie może być w przyszłości")
			return
		}
		from := ""
		if x.AwareAt != nil {
			from = x.AwareAt.UTC().Format(time.RFC3339)
		}
		t := req.AwareAt.UTC()
		change("aware_at", from, t.Format(time.RFC3339))
		x.AwareAt = &t
		nis2["aware_at"] = t
	}
	if x.Assignee != prev.Assignee && x.Assignee != "" {
		u, err := s.Store.UserByUsername(r.Context(), x.Assignee)
		if err != nil || u.Disabled || !s.permsOf(r.Context(), u.Role).Has("incidents", "write") {
			writeError(w, http.StatusBadRequest, "bad_assignee", "to konto nie może obsługiwać incydentów")
			return
		}
	}
	if len(act) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"incident": prev})
		return
	}
	upd, err := s.Incidents.UpdateIncident(r.Context(), x, act, now)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	if len(nis2) > 0 {
		s.audit(r, &a.user, "incident_nis2_changed", strconv.FormatInt(id, 10), nis2)
	}
	if x.Status != prev.Status {
		s.audit(r, &a.user, "incident_status_changed", strconv.FormatInt(id, 10), map[string]any{"from": prev.Status, "to": x.Status})
	}
	if upd.Significant && !prev.Significant {
		lang := s.systemLanguage(r.Context())
		s.notifyIncident(r.Context(), upd, notify.SevCritical, pick(lang, "Incydent poważny (NIS2): ", "Significant incident (NIS2): ")+upd.Title,
			pick(lang, "Incydent oznaczony jako poważny – liczą się terminy zgłoszeń do CSIRT (24 h, 72 h, miesiąc).",
				"The incident was marked as significant – the CSIRT reporting deadlines are running (24 h, 72 h, one month)."))
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": upd})
}

func (s *Server) addIncidentNote(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
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
	if req.Text == "" || len(req.Text) > 10000 {
		writeError(w, http.StatusBadRequest, "bad_note", "notatka: 1–10000 znaków")
		return
	}
	if err := s.Incidents.AddIncidentActivity(r.Context(), id, []store.IncidentActivity{{At: s.now(), Username: a.user.Username,
		Kind: "note", Text: req.Text}}, s.now()); err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// addIncidentEvidence: wpis o zleconej paczce dowodowej (eksport z Urd).
// Wymaga eksportu z archiwum i wglądu w incydenty; działa też po zamknięciu.
func (s *Server) addIncidentEvidence(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	if !a.perms.Has("incidents", "read") {
		writeError(w, http.StatusForbidden, "forbidden", "brak uprawnień do incydentów")
		return
	}
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	// Text – opis w języku zlecającego (zostaje w osi czasu); pola eksportu
	// pozwalają panelowi pokazać wpis w języku czytającego.
	var req struct {
		Text     string     `json:"text"`
		ExportID int64      `json:"export_id"`
		From     *time.Time `json:"from"`
		To       *time.Time `json:"to"`
		Agents   int        `json:"agents"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" || len(req.Text) > 2000 {
		writeError(w, http.StatusBadRequest, "bad_evidence", "opis paczki: 1–2000 znaków")
		return
	}
	var details map[string]any
	if req.ExportID > 0 && req.From != nil && req.To != nil {
		details = map[string]any{"export_id": req.ExportID, "from": req.From.UTC(), "to": req.To.UTC(), "agents": max(req.Agents, 0)}
	}
	if err := s.Incidents.AddIncidentEvidence(r.Context(), id, store.IncidentActivity{At: s.now(), Username: a.user.Username,
		Kind: "evidence", Text: req.Text, Details: details}); err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) addIncidentAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	var req struct {
		AlertIDs []int64 `json:"alert_ids"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.AlertIDs) == 0 {
		writeError(w, http.StatusBadRequest, "bad_alerts", "zaznacz alerty")
		return
	}
	now := s.now()
	snaps, err := s.snapshot(r.Context(), req.AlertIDs, a.user.Username, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_alerts", err)
		return
	}
	ids := make([]int64, len(snaps))
	for i, x := range snaps {
		ids[i] = x.AlertID
	}
	if err := s.Incidents.AddIncidentAlerts(r.Context(), id, snaps, store.IncidentActivity{At: now, Username: a.user.Username,
		Kind: "alerts_added", Text: fmt.Sprintf("dodane alerty: %d", len(snaps)), Details: map[string]any{"alert_ids": ids}}); err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) removeIncidentAlert(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny numer alertu")
		return
	}
	if err := s.Incidents.RemoveIncidentAlert(r.Context(), id, aid, store.IncidentActivity{At: s.now(), Username: a.user.Username,
		Kind: "alert_removed", Text: fmt.Sprintf("usunięty alert #%d", aid), Details: map[string]any{"alert_id": aid}}); err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- zgłoszenia do CSIRT ----

func reportKind(w http.ResponseWriter, r *http.Request) (string, bool) {
	k := r.PathValue("kind")
	if !slices.Contains(reportKinds, k) {
		writeError(w, http.StatusBadRequest, "bad_kind", "rodzaj zgłoszenia: early_warning, notification, intermediate albo final")
		return "", false
	}
	return k, true
}

// draftReport: szkic zgłoszenia z danych incydentu (do edycji przed wysłaniem).
func (s *Server) draftReport(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	kind, ok := reportKind(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	x, err := s.Incidents.Incident(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	als, err := s.Incidents.IncidentAlerts(ctx, id)
	if err != nil {
		s.incidentError(w, r, err)
		return
	}
	// Język szkicu: wybrany w edytorze (np. polski dla krajowego CSIRT),
	// domyślnie język systemu.
	lang := r.URL.Query().Get("lang")
	if !slices.Contains(syslang.Supported, lang) {
		lang = s.systemLanguage(ctx)
	}
	if lang != "pl" && s.Alerts != nil {
		for i, a := range als {
			if full, err := s.Alerts.Alert(ctx, a.AlertID); err == nil {
				t := full.Text(lang)
				als[i].RuleTitle, als[i].Summary = t.Title, t.Summary
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": reportDraft(kind, x, als, s.now(), lang), "language": lang})
}

func (s *Server) saveReport(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	kind, ok := reportKind(w, r)
	if !ok {
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Content) == "" || len(req.Content) > 100000 {
		writeError(w, http.StatusBadRequest, "bad_content", "treść zgłoszenia: 1–100000 znaków")
		return
	}
	if _, err := s.Incidents.Incident(r.Context(), id); err != nil {
		s.incidentError(w, r, err)
		return
	}
	if err := s.Incidents.SaveIncidentReport(r.Context(), id, kind, req.Content, a.user.Username, s.now()); err != nil {
		s.incidentError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// submitReport: zgłoszenie wysłane do CSIRT (poza Vardrem – portal, e-mail):
// treść zostaje zamrożona, z numerem sprawy i chwilą wysłania.
func (s *Server) submitReport(w http.ResponseWriter, r *http.Request) {
	if !s.incidentsEnabled(w) {
		return
	}
	a := current(r)
	id, ok := incidentID(w, r)
	if !ok {
		return
	}
	kind, ok := reportKind(w, r)
	if !ok {
		return
	}
	var req struct {
		Content     string     `json:"content"`
		Reference   string     `json:"reference"`
		SubmittedAt *time.Time `json:"submitted_at"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	at := now
	if req.SubmittedAt != nil {
		if req.SubmittedAt.After(now.Add(5 * time.Minute)) {
			writeError(w, http.StatusBadRequest, "bad_time", "chwila wysłania nie może być w przyszłości")
			return
		}
		at = *req.SubmittedAt
	}
	req.Reference = strings.TrimSpace(req.Reference)
	if strings.TrimSpace(req.Content) == "" || len(req.Content) > 100000 || len(req.Reference) > 200 {
		writeError(w, http.StatusBadRequest, "bad_content", "podaj treść wysłanego zgłoszenia (i ewentualnie numer sprawy, do 200 znaków)")
		return
	}
	if _, err := s.Incidents.Incident(r.Context(), id); err != nil {
		s.incidentError(w, r, err)
		return
	}
	if err := s.Incidents.SubmitIncidentReport(r.Context(), id, kind, req.Content, req.Reference, a.user.Username, at.UTC(), now); err != nil {
		s.incidentError(w, r, err)
		return
	}
	s.audit(r, &a.user, "incident_report_submitted", strconv.FormatInt(id, 10), map[string]any{"kind": kind,
		"reference": req.Reference, "submitted_at": at.UTC()})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// pick: tekst polski albo angielski (dla „en”).
func pick(lang, pl, en string) string {
	if lang == "en" {
		return en
	}
	return pl
}

// Nazwy statusów, wag i zgłoszeń po angielsku (szkice i powiadomienia).
var (
	statusLabelsEN   = map[string]string{"open": "open", "investigating": "investigating", "contained": "contained", "resolved": "resolved", "closed": "closed"}
	severityLabelsEN = map[string]string{"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
	reportLabelsEN   = map[string]string{"early_warning": "early warning", "notification": "incident notification",
		"intermediate": "intermediate report", "final": "final report"}
)

// label: nazwa z mapy polskiej albo angielskiej.
func label(lang string, pl, en map[string]string, k string) string {
	if lang == "en" {
		return en[k]
	}
	return pl[k]
}

// reportDraft: szkic zgłoszenia – struktura według art. 23 ust. 4 dyrektywy
// NIS2; pola „[uzupełnij]” wymagają wiedzy spoza Vardra. lang: pl albo en.
func reportDraft(kind string, x store.Incident, als []store.IncidentAlert, now time.Time, lang string) string {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if loc == nil {
		loc = time.UTC
	}
	tf := func(t time.Time) string { return t.In(loc).Format("2006-01-02 15:04") }
	tri := map[string]string{"yes": pick(lang, "tak", "yes"), "no": pick(lang, "nie", "no"), "unknown": pick(lang, "nieustalone", "not determined")}
	fill := pick(lang, "[uzupełnij]", "[to complete]")
	orBlank := func(s string) string {
		if strings.TrimSpace(s) == "" {
			return fill
		}
		return strings.TrimSpace(s)
	}
	var b strings.Builder
	line := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	title := label(lang, reportLabels, reportLabelsEN, kind)
	line(pick(lang, "%s – incydent #%d", "%s – incident #%d"), strings.ToUpper(title[:1])+title[1:], x.ID)
	line(pick(lang, "Przygotowano: %s (czas polski)", "Prepared: %s (Polish time)"), tf(now))
	line("")
	line(pick(lang, "1. Podmiot zgłaszający", "1. Reporting entity"))
	line(pick(lang, "   Nazwa podmiotu: %s", "   Entity name: %s"), fill)
	line(pick(lang, "   Sektor / rodzaj działalności: %s", "   Sector / type of activity: %s"), fill)
	line(pick(lang, "   Osoba do kontaktu (imię, telefon, e-mail): %s", "   Contact person (name, phone, e-mail): %s"), fill)
	line("")
	line(pick(lang, "2. Incydent", "2. Incident"))
	line(pick(lang, "   Tytuł: %s", "   Title: %s"), x.Title)
	if x.AwareAt != nil {
		line(pick(lang, "   Stwierdzony: %s", "   Became aware: %s"), tf(*x.AwareAt))
	}
	hosts, users := map[string]bool{}, map[string]bool{}
	var first, last time.Time
	for _, a := range als {
		if a.HostName != "" {
			hosts[a.HostName] = true
		}
		if a.UserName != "" {
			users[a.UserName] = true
		}
		if first.IsZero() || a.FirstSeen.Before(first) {
			first = a.FirstSeen
		}
		if a.LastSeen.After(last) {
			last = a.LastSeen
		}
	}
	if !first.IsZero() {
		line(pick(lang, "   Pierwsze wykryte zdarzenie: %s, ostatnie: %s", "   First detected event: %s, last: %s"), tf(first), tf(last))
	}
	line(pick(lang, "   Waga (ocena wewnętrzna): %s; status: %s", "   Severity (internal assessment): %s; status: %s"),
		label(lang, severityLabels, severityLabelsEN, x.Severity), label(lang, statusLabels, statusLabelsEN, x.Status))
	line(pick(lang, "   Opis: %s", "   Description: %s"), orBlank(x.Description))
	line(pick(lang, "   Podejrzenie działania bezprawnego lub złośliwego: %s", "   Suspected unlawful or malicious act: %s"), tri[x.Malicious])
	line(pick(lang, "   Możliwy wpływ transgraniczny: %s", "   Possible cross-border impact: %s"), tri[x.CrossBorder])
	if kind == "early_warning" {
		line("")
		line(pick(lang, "Wczesne ostrzeżenie (art. 23 ust. 4 lit. a) – szczegóły w zgłoszeniu incydentu w ciągu 72 h.",
			"Early warning (Article 23(4)(a)) – details in the incident notification within 72 h."))
		return b.String()
	}
	line("")
	line(pick(lang, "3. Wstępna ocena (powaga i skutki)", "3. Initial assessment (severity and impact)"))
	line(pick(lang, "   Skutki: %s", "   Impact: %s"), orBlank(x.Impact))
	line(pick(lang, "   Systemy, których dotyczy (%d): %s", "   Affected systems (%d): %s"), len(hosts), joinKeys(hosts, fill))
	line(pick(lang, "   Konta, których dotyczy (%d): %s", "   Affected accounts (%d): %s"), len(users), joinKeys(users, pick(lang, "brak w alertach", "none in the alerts")))
	line("")
	line(pick(lang, "4. Wskaźniki naruszenia (IoC)", "4. Indicators of compromise (IoC)"))
	line("   %s", orBlank(x.IOCs))
	line("")
	line(pick(lang, "5. Wykrycia (alerty Vardr, %d)", "5. Detections (Vardr alerts, %d)"), len(als))
	for i, a := range als {
		if i == 30 {
			line(pick(lang, "   … i %d kolejnych", "   … and %d more"), len(als)-30)
			break
		}
		line("   - %s [%s] %s – %s", tf(a.FirstSeen), a.Level, a.RuleTitle, a.Summary)
	}
	if kind == "final" || kind == "intermediate" {
		line("")
		line(pick(lang, "6. Rodzaj zagrożenia / pierwotna przyczyna", "6. Type of threat / root cause"))
		line("   %s", orBlank(x.RootCause))
		line("")
		line(pick(lang, "7. Zastosowane i prowadzone środki ograniczające", "7. Applied and ongoing mitigation measures"))
		line("   %s", orBlank(x.Mitigation))
	}
	if kind == "final" {
		line("")
		line(pick(lang, "8. Wpływ transgraniczny (jeśli wystąpił): %s", "8. Cross-border impact (if any): %s"), tri[x.CrossBorder])
	}
	return b.String()
}

func joinKeys(m map[string]bool, empty string) string {
	if len(m) == 0 {
		return empty
	}
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	if len(k) > 20 {
		k = append(k[:20], fmt.Sprintf("… (+%d)", len(m)-20))
	}
	return strings.Join(k, ", ")
}

// ---- przypomnienia o terminach ----

// RunIncidentReminders co 5 minut sprawdza terminy zgłoszeń NIS2 i wysyła
// przypomnienia na kanały (zdarzenie „incident”): przed upływem (24 h i 72 h –
// 6 h wcześniej; sprawozdanie końcowe – 3 dni) i po upływie terminu.
func (s *Server) RunIncidentReminders(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
		if s.Incidents == nil || s.Notify == nil {
			continue
		}
		list, err := s.Incidents.Incidents(ctx, "active")
		if err != nil {
			s.Log.Warn("przypomnienia o incydentach: lista", "err", err)
			continue
		}
		now := s.now()
		lang := s.systemLanguage(ctx)
		for _, x := range list {
			if !x.Significant || x.AwareAt == nil {
				continue
			}
			reps, err := s.Incidents.IncidentReports(ctx, x.ID)
			if err != nil {
				continue
			}
			for _, d := range deadlines(x, reps) {
				if d.SubmittedAt != nil {
					continue
				}
				lead := 6 * time.Hour
				if d.Kind == "final" {
					lead = 72 * time.Hour
				}
				stage, sev, text := "", "", ""
				name := label(lang, reportLabels, reportLabelsEN, d.Kind)
				switch {
				case now.After(d.Due):
					stage, sev = "overdue", notify.SevCritical
					text = fmt.Sprintf(pick(lang, "Termin minął %s – %s nie zostało oznaczone jako wysłane.",
						"The deadline passed at %s – the %s has not been marked as submitted."), d.Due.Format(time.RFC3339), name)
				case now.After(d.Due.Add(-lead)):
					stage, sev = "soon", notify.SevWarning
					text = fmt.Sprintf(pick(lang, "%s – termin %s (zostało %s).", "%s – due %s (%s left)."), name, d.Due.Format(time.RFC3339),
						d.Due.Sub(now).Round(time.Minute))
				default:
					continue
				}
				if fresh, err := s.Incidents.ReminderSent(ctx, x.ID, d.Kind, stage, now); err != nil || !fresh {
					continue
				}
				s.notifyIncident(ctx, x, sev, fmt.Sprintf(pick(lang, "NIS2: %s – incydent #%d", "NIS2: %s – incident #%d"), name, x.ID), text)
			}
		}
	}
}

func (s *Server) notifyIncident(ctx context.Context, x store.Incident, sev, title, text string) {
	if s.Notify == nil || s.Notify.Svc == nil {
		return
	}
	lang := s.systemLanguage(ctx)
	if _, err := s.Notify.Svc.Send(ctx, notify.Message{Event: notify.EventIncident, Severity: sev, Title: title, Text: text, At: s.now(),
		Fields: []notify.Field{{Name: pick(lang, "Incydent", "Incident"), Value: fmt.Sprintf("#%d %s", x.ID, x.Title)},
			{Name: "Status", Value: label(lang, statusLabels, statusLabelsEN, x.Status), Inline: true, Trusted: true},
			{Name: pick(lang, "Waga", "Severity"), Value: label(lang, severityLabels, severityLabelsEN, x.Severity), Inline: true, Trusted: true}}}); err != nil {
		s.Log.Warn("incident notification failed", "incident", x.ID, "err", err)
	}
}
