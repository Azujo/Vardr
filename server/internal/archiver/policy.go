// SPDX-License-Identifier: AGPL-3.0-or-later

package archiver

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"siem/internal/urd"
	"siem/server/internal/metrics"
)

// Powody pominięcia paczki przez archiwizator.
const (
	skipPrefix   = "prefix"   // SIEM_ARCHIVE_EXCLUDE_AGENTS (konfiguracja serwera)
	skipDisabled = "disabled" // polityka: archiwizacja wyłączona
	skipAgent    = "agent"    // polityka: agent wyłączony z archiwum
	skipGroup    = "group"    // polityka: grupa agenta wyłączona z archiwum
)

// Policy to obowiązująca polityka archiwum w postaci do szybkiego
// sprawdzania (pętla archiwizatora czyta ją przy każdej paczce, Maintain
// podmienia co minutę).
type Policy struct {
	Bounds urd.PolicyBounds
	// Grace: wykluczenie grupy obejmuje agenta dopiero po tym czasie od jego
	// wejścia do grupy (przeniesienie do wyłączonej grupy to też osłabienie).
	Grace time.Duration
	cur   atomic.Pointer[policyState]

	members map[string]urd.Membership // tylko gorutyna Maintain
}

type policyState struct {
	p           urd.Policy
	agents      map[string]bool
	groups      map[int64]bool
	assign      map[string]int64
	members     map[string]urd.Membership
	defGroup    int64
	groupsKnown bool
	grace       time.Duration
}

// NewPolicy tworzy politykę z wartością początkową.
func NewPolicy(p urd.Policy, b urd.PolicyBounds, grace time.Duration) *Policy {
	pol := &Policy{Bounds: b, Grace: grace}
	pol.Set(p, nil, nil, 0, false)
	return pol
}

// Set podmienia politykę, przypisania agentów do grup i czasy wejścia do
// grup (known = false: przypisania nieznane – wykluczenia grup nie działają,
// archiwum zbiera wszystko).
func (p *Policy) Set(pol urd.Policy, assign map[string]int64, members map[string]urd.Membership, defGroup int64, known bool) {
	st := &policyState{p: pol, agents: map[string]bool{}, groups: map[int64]bool{}, assign: assign, members: members,
		defGroup: defGroup, groupsKnown: known, grace: p.Grace}
	for _, a := range pol.ExcludedAgents {
		st.agents[a] = true
	}
	for _, g := range pol.ExcludedGroups {
		st.groups[g] = true
	}
	p.cur.Store(st)
}

// Current zwraca obowiązującą politykę.
func (p *Policy) Current() urd.Policy { return p.cur.Load().p }

// Retention zwraca retencję z polityki ograniczoną granicami z konfiguracji
// serwera – archiwizator nigdy nie usuwa danych wcześniej niż po minimum.
func (p *Policy) Retention() time.Duration {
	days := p.Current().RetentionDays
	if b := p.Bounds; b.MinRetentionDays > 0 && days < b.MinRetentionDays {
		days = b.MinRetentionDays
	}
	if b := p.Bounds; b.MaxRetentionDays > 0 && days > b.MaxRetentionDays {
		days = b.MaxRetentionDays
	}
	return time.Duration(max(1, days)) * 24 * time.Hour
}

// skip zwraca powód pominięcia paczki agenta albo "".
func (p *Policy) skip(agent string) string {
	st := p.cur.Load()
	switch {
	case !st.p.Enabled:
		return skipDisabled
	case st.agents[agent]:
		return skipAgent
	case st.groupsKnown && len(st.groups) > 0:
		if m, ok := st.members[agent]; ok {
			// Agent obserwowany: wykluczenie po karencji od wejścia do grupy.
			if st.groups[m.Group] && !time.Now().Before(m.Since.Add(st.grace)) {
				return skipGroup
			}
			return ""
		}
		if _, ok := st.assign[agent]; ok {
			return "" // świeżo przypisany – jeszcze nie obserwowany, archiwizujemy
		}
		// Bez przypisania: grupa domyślna; jej wykluczenie przeszło karencję polityki.
		if st.groups[st.defGroup] {
			return skipGroup
		}
	}
	return ""
}

// trackMembership aktualizuje czasy wejścia agentów do grup (zapis tylko
// zmian). Agent, który stracił przypisanie, przechodzi do grupy domyślnej.
func (p *Policy) trackMembership(ctx context.Context, s PolicyStore, assign map[string]int64, defGroup int64, now time.Time) error {
	if p.members == nil {
		m, err := s.GroupMembership(ctx)
		if err != nil {
			return err
		}
		p.members = m
	}
	changed := map[string]urd.Membership{}
	for a, g := range assign {
		if m, ok := p.members[a]; !ok || m.Group != g {
			changed[a] = urd.Membership{Group: g, Since: now}
		}
	}
	for a, m := range p.members {
		if _, ok := assign[a]; !ok && m.Group != defGroup {
			changed[a] = urd.Membership{Group: defGroup, Since: now}
		}
	}
	if err := s.SaveGroupMembership(ctx, changed); err != nil {
		return err
	}
	for a, m := range changed {
		p.members[a] = m
	}
	return nil
}

func (r *Archiver) skipReason(agent string) string {
	for _, p := range r.Cfg.ExcludeAgents {
		if p != "" && strings.HasPrefix(agent, p) {
			return skipPrefix
		}
	}
	if r.Policy != nil {
		return r.Policy.skip(agent)
	}
	return ""
}

// PolicyStore to polityka w bazie Saga (implementuje urd.PG).
type PolicyStore interface {
	ProcessPolicyChanges(ctx context.Context, b urd.PolicyBounds, grace time.Duration, now time.Time) ([]urd.PolicyChange, urd.Policy, error)
	ScheduledChange(ctx context.Context) (*urd.PolicyChange, error)
	SourceGroups(ctx context.Context) (map[string]int64, int64, bool, error)
	GroupMembership(ctx context.Context) (map[string]urd.Membership, error)
	SaveGroupMembership(ctx context.Context, changed map[string]urd.Membership) error
}

// refreshPolicy rozpatruje zlecenia zmian z panelu i odświeża politykę
// oraz przypisania agentów do grup. Przy błędzie bazy zostaje poprzednia.
func refreshPolicy(ctx context.Context, s PolicyStore, pol *Policy, grace time.Duration, log *slog.Logger, m *metrics.Archiver) {
	changed, cur, err := s.ProcessPolicyChanges(ctx, pol.Bounds, grace, time.Now().UTC())
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("processing policy changes failed – the previous one stays in force", "err", err)
		}
		return
	}
	for _, c := range changed {
		args := []any{"change", c.ID, "by", c.RequestedBy, "enabled", c.Enabled, "retention_days", c.RetentionDays,
			"excluded_groups", c.ExcludedGroups, "excluded_agents", c.ExcludedAgents, "reason", c.Reason}
		switch c.Status {
		case urd.PolicyApplied:
			log.Warn("archive policy changed", args...)
		case urd.PolicyScheduled:
			log.Warn("archive policy weakening scheduled", append(args, "weakening", c.Weakening, "effective_at", c.EffectiveAt)...)
		case urd.PolicyRejected:
			log.Warn("archive policy change rejected", append(args, "error", c.Error)...)
		default:
			log.Info("policy change request closed", "change", c.ID, "status", c.Status)
		}
	}
	assign, def, known, err := s.SourceGroups(ctx)
	if err != nil {
		log.Warn("reading agent groups failed – group exclusions temporarily do not work", "err", err)
	} else if !known && len(cur.ExcludedGroups) > 0 {
		log.Warn("no access to agent groups (panel tables) – group exclusions do not work, the archive collects everything")
	}
	known = known && err == nil
	if known {
		if err := pol.trackMembership(ctx, s, assign, def, time.Now().UTC()); err != nil {
			log.Warn("recording group membership failed – group exclusions temporarily do not work", "err", err)
			known = false
		}
	}
	members := make(map[string]urd.Membership, len(pol.members))
	for a, m := range pol.members {
		members[a] = m
	}
	pol.Set(cur, assign, members, def, known)

	sc, err := s.ScheduledChange(ctx)
	if err == nil {
		m.PolicyScheduled.Set(b2f(sc != nil))
	}
	m.PolicyEnabled.Set(b2f(cur.Enabled))
	m.PolicyRetentionDays.Set(pol.Retention().Hours() / 24)
	m.PolicyExcluded.Set(float64(len(cur.ExcludedGroups) + len(cur.ExcludedAgents)))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
