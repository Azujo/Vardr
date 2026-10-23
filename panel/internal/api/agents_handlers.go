// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"

	"siem/internal/contract"
	"siem/panel/internal/api/store"
)

// Agent jest offline po 3 interwałach heartbeatu bez sygnału.
const offlineAfter = 3 * contract.HeartbeatInterval

// Certyfikat agenta „wkrótce wygasa” na tyle dni przed końcem ważności.
const certWarnDays = 14

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// agentStatus to fragment status.json agenta potrzebny do podsumowania
// (pełny dokument trafia do szczegółów bez zmian).
type agentStatus struct {
	Server struct {
		Healthy        bool       `json:"healthy"`
		LastAcceptedAt *time.Time `json:"last_accepted_at"`
		LastError      string     `json:"last_error"`
	} `json:"server"`
	Counters struct {
		Read        int64 `json:"read"`
		Accepted    int64 `json:"accepted"`
		Quarantined int64 `json:"quarantined"`
		Retries     int64 `json:"retries"`
	} `json:"counters"`
	Channels []struct {
		Name  string `json:"name"`
		State string `json:"state"`
		Error string `json:"error"`
	} `json:"channels"`
	Warnings []string `json:"warnings"`
	Buffer   *struct {
		Batches  int       `json:"batches"`
		Bytes    int64     `json:"bytes"`
		OldestAt time.Time `json:"oldest_at"`
		Dropped  int64     `json:"dropped_events"`
		Full     bool      `json:"full"`
	} `json:"buffer"`
	Sysmon *struct {
		Installed  bool   `json:"installed"`
		Running    bool   `json:"running"`
		Version    string `json:"version"`
		ConfigHash string `json:"config_hash"`
	} `json:"sysmon"`
	Protection *contract.ProtectionStatus `json:"protection"`
	Stopping   string                     `json:"stopping"`
	Clock      struct {
		OffsetMs      int64     `json:"offset_ms"`
		UncertaintyMs int64     `json:"uncertainty_ms"`
		MeasuredAt    time.Time `json:"measured_at"`
		TimeService   string    `json:"time_service"`
	} `json:"clock"`
}

// clockTolerance: odchylenie zegara agenta od serwera, od którego panel
// zgłasza problem (czasy zdarzeń przestają się zgadzać; Kerberos toleruje 5 min).
const clockTolerance = 60 * time.Second

// agentView to agent na liście w panelu.
type agentView struct {
	ID           string     `json:"id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	Version      string     `json:"version"`
	RemoteIP     string     `json:"remote_ip"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	CertDaysLeft *int       `json:"cert_days_left,omitempty"`

	State          string     `json:"state"` // online | offline | retired (certyfikat unieważniony)
	ServerHealthy  bool       `json:"server_healthy"`
	LastAcceptedAt *time.Time `json:"last_accepted_at,omitempty"`
	Accepted       int64      `json:"events_accepted"`
	Read           int64      `json:"events_read"`
	Quarantined    int64      `json:"events_quarantined"`
	Warnings       int        `json:"warnings"`
	LastWarning    string     `json:"last_warning,omitempty"`
	ChannelsOK     int        `json:"channels_ok"`
	ChannelsTotal  int        `json:"channels_total"`
	// Konfiguracja z panelu: grupa, wersja oczekiwana i zastosowana przez agenta.
	GroupID        int64  `json:"group_id"`
	Group          string `json:"group"`
	ConfigExpected string `json:"config_expected"`
	ConfigApplied  string `json:"config_applied,omitempty"`
	ConfigState    string `json:"config_state"` // applied | pending | unknown
	// Sysmon: running | stopped | missing | unknown (agent starszy niż 0.6.2).
	Sysmon         string `json:"sysmon"`
	SysmonVersion  string `json:"sysmon_version,omitempty"`
	SysmonConfig   string `json:"sysmon_config,omitempty"`
	SysmonRequired bool   `json:"sysmon_required"`
	// Ochrona agenta: protected | open | off (wyłączona w grupie) | error |
	// unknown (agent bez ochrony – starsza wersja, kolektor, konektor).
	Protection      string `json:"protection"`
	ProtectionError string `json:"protection_error,omitempty"`
	// Tamper: zdarzenia ochrony z alertem z ostatnich 24 h.
	Tamper int `json:"tamper_24h"`
	// Stopping: powód zatrzymania z ostatniego heartbeatu (agent offline).
	Stopping string `json:"stopping,omitempty"`
	// Problems to czytelne opisy problemów (pusta lista = wszystko w porządku).
	Problems []string `json:"problems"`
	// Issues: te same problemy jako kod z parametrami – panel pokazuje je
	// w języku użytkownika (Problems – po polsku, zapasowo).
	Issues []agentIssue `json:"issues"`
}

type agentIssue struct {
	Code string         `json:"code"`
	Args map[string]any `json:"args,omitempty"`
}

// problem dopisuje problem agenta: kod z parametrami i polski opis.
func (v *agentView) problem(code, text string, args map[string]any) {
	v.Problems = append(v.Problems, text)
	v.Issues = append(v.Issues, agentIssue{Code: code, Args: args})
}

func viewAgent(a store.Agent, g store.AgentGroup, now time.Time) agentView {
	v := agentView{
		GroupID: g.ID, Group: g.Name, ConfigExpected: g.Config().Version,
		ID: a.ID, Hostname: a.Hostname, OS: a.OS, Version: a.Version, RemoteIP: a.RemoteIP,
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, StartedAt: a.StartedAt, CertNotAfter: a.CertNotAfter,
		State: "online", Problems: []string{}, Issues: []agentIssue{},
	}
	v.SysmonRequired = g.Limits.RequireSysmon != nil && *g.Limits.RequireSysmon

	v.ConfigApplied, v.ConfigState = agentConfigState(a.Status, v.ConfigExpected)
	var st agentStatus
	stErr := json.Unmarshal(a.Status, &st)
	if now.Sub(a.LastSeen) > offlineAfter {
		v.State = "offline"
		v.Stopping = st.Stopping
		since := map[string]any{"s": int(now.Sub(a.LastSeen).Seconds())}
		switch st.Stopping {
		case "":
			v.problem("no_heartbeat", "brak heartbeatu od "+humanAgo(now.Sub(a.LastSeen)), since)
		case "shutdown":
			v.problem("shutdown", "komputer wyłączony "+humanAgo(now.Sub(a.LastSeen))+" temu", since)
		default:
			since["how"] = st.Stopping
			v.problem("stopped", "agent zatrzymany ("+stoppingLabel(st.Stopping)+") "+humanAgo(now.Sub(a.LastSeen))+" temu", since)
		}
	}
	// Wycofany: certyfikat unieważniony (deinstalacja tokenem albo panel) –
	// agent nie może już nic wysłać; to nie problem, tylko stan.
	if a.CertRevoked {
		v.State, v.Problems, v.Issues = "retired", []string{}, []agentIssue{}
		return v
	}
	if a.CertNotAfter != nil {
		days := int(a.CertNotAfter.Sub(now).Hours() / 24)
		v.CertDaysLeft = &days
		switch {
		case days < 0:
			v.problem("cert_expired", "certyfikat agenta wygasł", nil)
		case days < certWarnDays:
			v.problem("cert_expiring", fmt.Sprintf("certyfikat wygasa za %d dni", days), map[string]any{"days": days})
		}
	}

	if stErr != nil {
		v.problem("bad_status", "nieczytelny status agenta", nil)
		return v
	}
	v.Protection = "unknown"
	if p := st.Protection; p != nil {
		v.Protection, v.ProtectionError = p.Service, p.Error
		if !p.Enabled {
			v.Protection = "off"
		}
		if p.Enabled && p.Service != "protected" && v.State == "online" {
			msg := "ochrona usługi agenta nie działa"
			if p.Error != "" {
				msg += ": " + truncate(p.Error, 120)
			}
			v.problem("protection_down", msg, map[string]any{"error": truncate(p.Error, 120)})
		}
		for _, e := range p.Events {
			if contract.TamperKinds[e.Kind].Level != "" && now.Sub(e.At) < 24*time.Hour {
				v.Tamper++
			}
		}
		if v.Tamper > 0 {
			v.problem("tamper", fmt.Sprintf("próby sabotażu agenta w ostatniej dobie: %d (szczegóły agenta)", v.Tamper), map[string]any{"n": v.Tamper})
		}
	}
	v.ServerHealthy, v.LastAcceptedAt = st.Server.Healthy, st.Server.LastAcceptedAt
	v.Accepted, v.Read, v.Quarantined = st.Counters.Accepted, st.Counters.Read, st.Counters.Quarantined
	v.Warnings = len(st.Warnings)
	if v.Warnings > 0 {
		v.LastWarning = st.Warnings[len(st.Warnings)-1]
	}
	v.ChannelsTotal = len(st.Channels)
	for _, c := range st.Channels {
		switch c.State {
		case "ok", "starting":
			v.ChannelsOK++
		case "not_found": // np. Sysmon niezainstalowany – informacja, nie awaria
		default:
			v.problem("channel", fmt.Sprintf("kanał %s: %s", c.Name, channelStateLabel(c.State)), map[string]any{"channel": c.Name, "state": c.State})
		}
	}
	if v.State == "online" && !st.Server.Healthy && st.Server.LastError != "" {
		v.problem("send_failed", "wysyłka zdarzeń nieudana: "+truncate(st.Server.LastError, 120), map[string]any{"error": truncate(st.Server.LastError, 120)})
	}
	if st.Counters.Quarantined > 0 {
		v.problem("quarantined", fmt.Sprintf("%d zdarzeń w kwarantannie agenta", st.Counters.Quarantined), map[string]any{"n": st.Counters.Quarantined})
	}
	if b := st.Buffer; b != nil {
		if b.Batches > 0 && !b.OldestAt.IsZero() && now.Sub(b.OldestAt) > 5*time.Minute {
			v.problem("buffer_backlog", fmt.Sprintf("bufor dyskowy: %d paczek (%.1f MB) czeka na wysyłkę od %s",
				b.Batches, float64(b.Bytes)/(1<<20), humanAgo(now.Sub(b.OldestAt))),
				map[string]any{"batches": b.Batches, "bytes": b.Bytes, "s": int(now.Sub(b.OldestAt).Seconds())})
		}
		if b.Full {
			v.problem("buffer_full", "bufor dyskowy agenta pełny", nil)
		}
		if b.Dropped > 0 {
			v.problem("buffer_dropped", fmt.Sprintf("utracono %d zdarzeń z pełnego bufora dyskowego", b.Dropped), map[string]any{"n": b.Dropped})
		}
	}
	v.Sysmon = "unknown"
	if m := st.Sysmon; m != nil {
		v.SysmonVersion, v.SysmonConfig = m.Version, m.ConfigHash
		switch {
		case !m.Installed:
			v.Sysmon = "missing"
		case m.Running:
			v.Sysmon = "running"
		default:
			v.Sysmon = "stopped"
		}
	}
	if v.SysmonRequired {
		switch v.Sysmon {
		case "missing":
			v.problem("sysmon_missing", "Sysmon wymagany w grupie – nie jest zainstalowany", nil)
		case "stopped":
			v.problem("sysmon_stopped", "Sysmon zainstalowany, ale zatrzymany", nil)
		case "unknown":
			v.problem("sysmon_unknown", "Sysmon wymagany w grupie – agent nie raportuje jego stanu (zaktualizuj do 0.6.2+)", nil)
		}
	}
	c := st.Clock
	if !c.MeasuredAt.IsZero() {
		off := time.Duration(c.OffsetMs) * time.Millisecond
		if off < 0 {
			off = -off
		}
		if off-time.Duration(c.UncertaintyMs)*time.Millisecond > clockTolerance {
			dir := "spieszy się"
			if c.OffsetMs < 0 {
				dir = "spóźnia się"
			}
			v.problem("clock", fmt.Sprintf("zegar komputera %s o %s względem serwera", dir, off.Round(time.Second)),
				map[string]any{"ahead": c.OffsetMs > 0, "s": int(off.Round(time.Second).Seconds())})
		}
	}
	// „stopped” to zwykły stan na komputerach spoza domeny: Windows
	// uruchamia W32Time na żądanie. Problemem jest wyłączona albo brak
	// usługi (o rozjechanym zegarze i tak mówi pomiar odchylenia).
	switch c.TimeService {
	case "disabled", "missing":
		v.problem("w32time", "usługa czasu Windows (W32Time) wyłączona – zegar nie jest synchronizowany", nil)
	}
	return v
}

func stoppingLabel(s string) string {
	switch s {
	case contract.TamperStop:
		return "bez tokenu"
	case contract.TamperStopToken:
		return "tokenem"
	case contract.TamperUninstallTok:
		return "deinstalacja tokenem"
	case contract.TamperUpgrade:
		return "aktualizacja"
	}
	return s
}

func channelStateLabel(s string) string {
	switch s {
	case "access_denied":
		return "brak dostępu"
	case "error":
		return "błąd odczytu"
	}
	return s
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d dni", int(d.Hours()/24))
}

type agentsSummary struct {
	Total    int `json:"total"`
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	Retired  int `json:"retired"`
	Problems int `json:"with_problems"`
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.Store.ListAgents(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	groupOf, err := s.groupResolver(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := s.now()
	views := make([]agentView, 0, len(agents))
	for _, a := range agents {
		views = append(views, viewAgent(a, groupOf(a.ID), now))
	}
	applySysmonBaseline(views)
	var sum agentsSummary
	for _, v := range views {
		switch v.State {
		case "retired":
			sum.Retired++
			continue // poza liczbą agentów i problemami
		case "online":
			sum.Online++
		default:
			sum.Offline++
		}
		sum.Total++
		if len(v.Problems) > 0 {
			sum.Problems++
		}
	}
	// Najpierw agenci z problemami, potem alfabetycznie.
	sort.SliceStable(views, func(i, j int) bool {
		pi, pj := len(views[i].Problems) > 0, len(views[j].Problems) > 0
		if pi != pj {
			return pi
		}
		return views[i].ID < views[j].ID
	})
	writeJSON(w, http.StatusOK, map[string]any{"agents": views, "summary": sum, "offline_after_s": int(offlineAfter.Seconds())})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return
	}
	a, err := s.Store.AgentByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego agenta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	g, err := s.Store.GroupForAgent(r.Context(), id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	v := viewAgent(a, g, s.now())
	if v.SysmonRequired && v.SysmonConfig != "" {
		// Wzorzec konfiguracji Sysmona: większość agentów tej samej grupy.
		if all, err := s.Store.ListAgents(r.Context()); err == nil {
			if groupOf, err := s.groupResolver(r); err == nil {
				views := []agentView{}
				for _, x := range all {
					if gx := groupOf(x.ID); gx.ID == g.ID && x.ID != a.ID {
						views = append(views, viewAgent(x, gx, s.now()))
					}
				}
				views = append(views, v)
				applySysmonBaseline(views)
				v = views[len(views)-1]
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": v, "status": a.Status})
}

// orphanCerts: ważne certyfikaty agentów spoza listy (administrator je
// unieważnia – POST /agents/{id}/revoke działa także bez wiersza agenta).
func (s *Server) orphanCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.Store.OrphanAgentCerts(r.Context(), s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if certs == nil {
		certs = []store.AgentCert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return
	}
	// Usunięcie zawsze unieważnia certyfikaty: wiersz znika z listy, więc
	// ważny certyfikat (i klucz, który mógł zostać na dysku) byłby
	// niewidocznym dostępem do serwera. Agent, który nadal działa, nie
	// wróci już na listę – potrzebna nowa rejestracja tokenem.
	reason := pick(s.systemLanguage(r.Context()), "agent usunięty w panelu", "agent deleted in the panel")
	serials, err := s.Store.RevokeAgentCerts(r.Context(), id, reason)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(serials) > 0 && s.Enroll != nil && s.Enroll.Revoke != nil {
		if err := s.Enroll.Revoke(r.Context(), serials, reason); err != nil {
			s.internalError(w, r, fmt.Errorf("broadcasting the revocation: %w", err))
			return
		}
	}
	if err := s.Store.DeleteAgent(r.Context(), id); errors.Is(err, store.ErrNotFound) && len(serials) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego agenta")
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "agent_removed", id, map[string]any{"revoked_serials": serials})
	w.WriteHeader(http.StatusNoContent)
}

// groupResolver wczytuje grupy i przypisania raz na żądanie i zwraca
// funkcję agent → grupa (domyślna dla agentów bez przypisania).
func (s *Server) groupResolver(r *http.Request) (func(agentID string) store.AgentGroup, error) {
	groups, err := s.Store.ListGroups(r.Context())
	if err != nil {
		return nil, err
	}
	assign, err := s.Store.AgentGroupIDs(r.Context())
	if err != nil {
		return nil, err
	}
	byID := map[int64]store.AgentGroup{}
	var def store.AgentGroup
	for _, g := range groups {
		byID[g.ID] = g
		if g.IsDefault {
			def = g
		}
	}
	return func(agentID string) store.AgentGroup {
		if id, ok := assign[agentID]; ok {
			if g, ok := byID[id]; ok {
				return g
			}
		}
		return def
	}, nil
}

// applySysmonBaseline: w grupach wymagających Sysmona konfiguracja każdego
// komputera powinna być taka jak u większości grupy (ta sama wersja reguł).
func applySysmonBaseline(views []agentView) {
	counts := map[int64]map[string]int{}
	for _, v := range views {
		if v.SysmonRequired && v.SysmonConfig != "" {
			if counts[v.GroupID] == nil {
				counts[v.GroupID] = map[string]int{}
			}
			counts[v.GroupID][v.SysmonConfig]++
		}
	}
	for i := range views {
		v := &views[i]
		c := counts[v.GroupID]
		if !v.SysmonRequired || v.SysmonConfig == "" || len(c) < 2 {
			continue
		}
		best, n := "", 0
		for h, k := range c {
			if k > n || (k == n && h < best) {
				best, n = h, k
			}
		}
		if v.SysmonConfig != best {
			v.problem("sysmon_config", fmt.Sprintf("konfiguracja Sysmona (%s) inna niż u większości grupy (%s)", v.SysmonConfig, best),
				map[string]any{"config": v.SysmonConfig, "common": best})
		}
	}
}
