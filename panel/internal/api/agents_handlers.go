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
}

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

	State          string     `json:"state"` // online | offline
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
	// Problems to czytelne opisy problemów (pusta lista = wszystko w porządku).
	Problems []string `json:"problems"`
}

func viewAgent(a store.Agent, g store.AgentGroup, now time.Time) agentView {
	v := agentView{
		GroupID: g.ID, Group: g.Name, ConfigExpected: g.Config().Version,
		ID: a.ID, Hostname: a.Hostname, OS: a.OS, Version: a.Version, RemoteIP: a.RemoteIP,
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, StartedAt: a.StartedAt, CertNotAfter: a.CertNotAfter,
		State: "online", Problems: []string{},
	}
	v.ConfigApplied, v.ConfigState = agentConfigState(a.Status, v.ConfigExpected)
	if now.Sub(a.LastSeen) > offlineAfter {
		v.State = "offline"
		v.Problems = append(v.Problems, "brak heartbeatu od "+humanAgo(now.Sub(a.LastSeen)))
	}
	if a.CertNotAfter != nil {
		days := int(a.CertNotAfter.Sub(now).Hours() / 24)
		v.CertDaysLeft = &days
		switch {
		case days < 0:
			v.Problems = append(v.Problems, "certyfikat agenta wygasł")
		case days < certWarnDays:
			v.Problems = append(v.Problems, fmt.Sprintf("certyfikat wygasa za %d dni", days))
		}
	}

	var st agentStatus
	if err := json.Unmarshal(a.Status, &st); err != nil {
		v.Problems = append(v.Problems, "nieczytelny status agenta")
		return v
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
			v.Problems = append(v.Problems, fmt.Sprintf("kanał %s: %s", c.Name, channelStateLabel(c.State)))
		}
	}
	if v.State == "online" && !st.Server.Healthy && st.Server.LastError != "" {
		v.Problems = append(v.Problems, "wysyłka zdarzeń nieudana: "+truncate(st.Server.LastError, 120))
	}
	if st.Counters.Quarantined > 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("%d zdarzeń w kwarantannie agenta", st.Counters.Quarantined))
	}
	return v
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
	var sum agentsSummary
	for _, a := range agents {
		v := viewAgent(a, groupOf(a.ID), now)
		views = append(views, v)
		sum.Total++
		if v.State == "online" {
			sum.Online++
		} else {
			sum.Offline++
		}
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
	writeJSON(w, http.StatusOK, map[string]any{"agent": viewAgent(a, g, s.now()), "status": a.Status})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	a := current(r)
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator agenta")
		return
	}
	if err := s.Store.DeleteAgent(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "nie ma takiego agenta")
		return
	} else if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "agent_removed", id, nil)
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
