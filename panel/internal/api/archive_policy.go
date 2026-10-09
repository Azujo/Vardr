package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"siem/internal/urd"
	"siem/panel/internal/api/auth"
	"siem/panel/internal/api/store"
)

// unarchivedSource to agent, którego paczki nie trafiają do archiwum.
type unarchivedSource struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Group    string `json:"group"`
	Reason   string `json:"reason"` // disabled | agent | group | group_pending | prefix
	// EffectiveAt: dla group_pending – kiedy wykluczenie obejmie agenta
	// (karencja od wejścia do wyłączonej grupy; do tego czasu jest archiwizowany).
	EffectiveAt *time.Time `json:"effective_at,omitempty"`
}

// policyBounds to granice z konfiguracji serwera (ze stanu archiwizatora).
type policyBounds struct {
	MinRetentionDays int      `json:"min_retention_days"`
	MaxRetentionDays int      `json:"max_retention_days"`
	GraceS           int      `json:"grace_s"`
	ExcludePrefixes  []string `json:"exclude_prefixes"`
}

func boundsOf(o urd.Overview) policyBounds {
	b := policyBounds{ExcludePrefixes: []string{}}
	if st := o.State; st != nil {
		b.MinRetentionDays, b.MaxRetentionDays, b.GraceS = st.MinRetentionDays, st.MaxRetentionDays, st.PolicyGraceS
		if st.ExcludePrefixes != nil {
			b.ExcludePrefixes = st.ExcludePrefixes
		}
	}
	return b
}

// archivePolicy zwraca politykę archiwum, granice, historię zmian i listę
// źródeł bez archiwizacji.
func (s *Server) archivePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	ctx := r.Context()
	o, err := s.Archive.Overview(ctx)
	if errors.Is(err, urd.ErrNotConfigured) {
		writeJSON(w, http.StatusOK, map[string]any{"policy": nil, "changes": []urd.PolicyChange{}, "unarchived": []unarchivedSource{},
			"bounds": policyBounds{ExcludePrefixes: []string{}}})
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	changes, err := s.Archive.PolicyChanges(ctx, 50)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if changes == nil {
		changes = []urd.PolicyChange{}
	}
	b := boundsOf(o)
	unarchived := []unarchivedSource{}
	agentsTotal := 0
	if o.Policy != nil {
		agents, err := s.Store.ListAgents(ctx)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		groupOf, err := s.groupResolver(r)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		assign, err := s.Store.AgentGroupIDs(ctx)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		members, err := s.Archive.GroupMembership(ctx)
		if err != nil && !errors.Is(err, urd.ErrNotConfigured) {
			s.internalError(w, r, err)
			return
		}
		grace := time.Duration(b.GraceS) * time.Second
		agentsTotal = len(agents)
		for _, a := range agents {
			g := groupOf(a.ID)
			reason := ""
			var effective *time.Time
			switch {
			case slices.ContainsFunc(b.ExcludePrefixes, func(p string) bool { return p != "" && strings.HasPrefix(a.ID, p) }):
				reason = "prefix"
			case !o.Policy.Enabled:
				reason = "disabled"
			case slices.Contains(o.Policy.ExcludedAgents, a.ID):
				reason = "agent"
			case slices.Contains(o.Policy.ExcludedGroups, g.ID):
				// Jak w archiwizatorze: wykluczenie po karencji od wejścia do grupy.
				reason = "group"
				m, tracked := members[a.ID]
				_, assigned := assign[a.ID]
				switch {
				case tracked && m.Group == g.ID && s.now().Before(m.Since.Add(grace)):
					at := m.Since.Add(grace)
					reason, effective = "group_pending", &at
				case !tracked && assigned, tracked && m.Group != g.ID:
					reason = "group_pending" // archiwizator jeszcze nie zauważył przeniesienia
				}
			}
			if reason != "" {
				unarchived = append(unarchived, unarchivedSource{AgentID: a.ID, Hostname: a.Hostname, Group: g.Name, Reason: reason,
					EffectiveAt: effective})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":           o.Policy,
		"scheduled_change": o.ScheduledChange,
		"bounds":           b,
		"changes":          changes,
		"unarchived":       unarchived,
		"agents_total":     agentsTotal,
	})
}

type policyRequest struct {
	Enabled        bool     `json:"enabled"`
	RetentionDays  int      `json:"retention_days"`
	ExcludedGroups []int64  `json:"excluded_groups"`
	ExcludedAgents []string `json:"excluded_agents"`
	Reason         string   `json:"reason"`
	// Password: ponowne uwierzytelnienie – wymagane, gdy zmiana osłabia
	// ochronę (wyłączenie, krótsza retencja, wyłączenie źródła).
	Password string `json:"password"`
}

// changeArchivePolicy składa zlecenie zmiany polityki. Rozpatruje je
// archiwizator: wzmocnienie od razu, osłabienie po karencji (alert).
func (s *Server) changeArchivePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	ctx := r.Context()
	var req policyRequest
	if !readJSON(w, r, &req) {
		return
	}
	o, err := s.Archive.Overview(ctx)
	if errors.Is(err, urd.ErrNotConfigured) || (err == nil && o.Policy == nil) {
		writeError(w, http.StatusConflict, "archive_not_configured", "archiwizator jeszcze nie zapisał polityki – uruchom go najpierw")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	cur, b := *o.Policy, boundsOf(o)

	req.Reason = strings.TrimSpace(req.Reason)
	agents := make([]string, 0, len(req.ExcludedAgents))
	for _, ag := range req.ExcludedAgents {
		if ag = strings.TrimSpace(ag); ag != "" && !slices.Contains(agents, ag) {
			agents = append(agents, ag)
		}
	}
	slices.Sort(agents)
	groups := []int64{}
	for _, g := range req.ExcludedGroups {
		if !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	slices.Sort(groups)
	known, err := s.Store.ListGroups(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, g := range groups {
		// Grupa usunięta po wyłączeniu z archiwum może zostać na liście.
		if !slices.ContainsFunc(known, func(k store.AgentGroup) bool { return k.ID == g }) && !slices.Contains(cur.ExcludedGroups, g) {
			writeError(w, http.StatusBadRequest, "bad_group", "nie ma grupy agentów o numerze "+strconv.FormatInt(g, 10))
			return
		}
	}
	switch {
	case len(agents) > 1000 || len(groups) > 1000:
		writeError(w, http.StatusBadRequest, "bad_sources", "najwyżej 1000 agentów i 1000 grup wyłączonych z archiwum")
		return
	case slices.ContainsFunc(agents, func(s string) bool { return len(s) > 128 }):
		writeError(w, http.StatusBadRequest, "bad_sources", "identyfikator agenta może mieć najwyżej 128 znaków")
		return
	case req.RetentionDays < 1:
		writeError(w, http.StatusBadRequest, "bad_retention", "podaj retencję w dniach")
		return
	case len([]rune(req.Reason)) < 5 || len(req.Reason) > 1000:
		writeError(w, http.StatusBadRequest, "bad_reason", "podaj powód zmiany (5–1000 znaków) – trafi do audytu i historii polityki")
		return
	}
	if err := (urd.PolicyBounds{MinRetentionDays: b.MinRetentionDays, MaxRetentionDays: b.MaxRetentionDays}).Check(req.RetentionDays); err != nil {
		writeError(w, http.StatusBadRequest, "bad_retention", err.Error())
		return
	}
	target := urd.Policy{Enabled: req.Enabled, RetentionDays: req.RetentionDays, ExcludedGroups: groups, ExcludedAgents: agents}
	if target.Enabled == cur.Enabled && target.RetentionDays == cur.RetentionDays &&
		slices.Equal(target.ExcludedGroups, sortedInts(cur.ExcludedGroups)) && slices.Equal(target.ExcludedAgents, sortedStrings(cur.ExcludedAgents)) &&
		o.ScheduledChange == nil {
		writeError(w, http.StatusBadRequest, "no_change", "polityka jest już taka – nic do zmiany")
		return
	}

	weakening := urd.Weakening(cur, target)
	if len(weakening) > 0 && !s.reauth(w, r, req.Password, "archive_policy_change") {
		return
	}
	c, err := s.Archive.CreatePolicyChange(ctx, urd.PolicyChange{RequestedBy: a.user.Username, Reason: req.Reason,
		Enabled: target.Enabled, RetentionDays: target.RetentionDays, ExcludedGroups: groups, ExcludedAgents: agents,
		Reauth: len(weakening) > 0})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_policy_change_requested", "urd", map[string]any{
		"change_id": c.ID, "enabled": target.Enabled, "retention_days": target.RetentionDays,
		"excluded_groups": groups, "excluded_agents": agents, "weakening": weakening, "reason": req.Reason,
		"previous": map[string]any{"enabled": cur.Enabled, "retention_days": cur.RetentionDays,
			"excluded_groups": cur.ExcludedGroups, "excluded_agents": cur.ExcludedAgents}})
	msg := "zmiana zlecona – archiwizator zastosuje ją w ciągu minuty"
	if len(weakening) > 0 {
		msg = "zmiana osłabia ochronę archiwum – wejdzie w życie po karencji; do tego czasu można ją anulować"
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"change": c, "weakening": weakening, "grace_s": b.GraceS, "message": msg})
}

// cancelArchivePolicyChange anuluje zmianę, która jeszcze nie weszła w życie.
// Anulowanie nie osłabia ochrony, więc nie wymaga ponownego uwierzytelnienia.
func (s *Server) cancelArchivePolicyChange(w http.ResponseWriter, r *http.Request) {
	if !s.archiveEnabled(w) {
		return
	}
	a := current(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_id", "niepoprawny identyfikator")
		return
	}
	c, err := s.Archive.CancelPolicyChange(r.Context(), id, a.user.Username, s.now())
	if errors.Is(err, urd.ErrPolicyChangeClosed) {
		writeError(w, http.StatusConflict, "change_closed", "zmiana już weszła w życie albo została zamknięta")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, &a.user, "archive_policy_change_cancelled", "urd", map[string]any{"change_id": c.ID, "requested_by": c.RequestedBy})
	writeJSON(w, http.StatusOK, map[string]any{"change": c, "message": "zmiana anulowana – archiwizator zamknie ją w ciągu minuty"})
}

// reauth sprawdza ponownie hasło zalogowanego użytkownika przed operacją
// osłabiającą ochronę. Błędne hasło liczy się do blokady konta jak przy
// logowaniu (ochrona przed zgadywaniem na przejętej sesji).
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, password, op string) bool {
	a := current(r)
	if password == "" {
		writeError(w, http.StatusForbidden, "reauth_required", "ta zmiana osłabia ochronę – potwierdź ją swoim hasłem")
		return false
	}
	now := s.now()
	if a.user.LockedUntil != nil && a.user.LockedUntil.After(now) {
		auth.DummyVerify(password)
		s.audit(r, &a.user, "reauth_failed", a.user.Username, map[string]any{"operation": op, "reason": "locked"})
		writeError(w, http.StatusForbidden, "reauth_failed", "konto jest czasowo zablokowane po nieudanych próbach – spróbuj później")
		return false
	}
	ok, _, err := auth.VerifyPassword(a.user.PasswordHash, password)
	if err != nil {
		s.internalError(w, r, err)
		return false
	}
	if !ok {
		reason := "bad_password"
		if until, err := s.Store.RecordLoginFailure(r.Context(), a.user.ID, s.LockAfter, s.LockFor); err == nil && until != nil && until.After(now) {
			reason = "bad_password_locked"
		}
		s.audit(r, &a.user, "reauth_failed", a.user.Username, map[string]any{"operation": op, "reason": reason})
		writeError(w, http.StatusForbidden, "reauth_failed", "hasło jest nieprawidłowe")
		return false
	}
	return true
}

func sortedInts(s []int64) []int64 {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

func sortedStrings(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}
