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
	cur    atomic.Pointer[policyState]
}

type policyState struct {
	p           urd.Policy
	agents      map[string]bool
	groups      map[int64]bool
	assign      map[string]int64
	defGroup    int64
	groupsKnown bool
}

// NewPolicy tworzy politykę z wartością początkową.
func NewPolicy(p urd.Policy, b urd.PolicyBounds) *Policy {
	pol := &Policy{Bounds: b}
	pol.Set(p, nil, 0, false)
	return pol
}

// Set podmienia politykę i przypisania agentów do grup (known = false:
// przypisania nieznane – wykluczenia grup nie działają, archiwum zbiera wszystko).
func (p *Policy) Set(pol urd.Policy, assign map[string]int64, defGroup int64, known bool) {
	st := &policyState{p: pol, agents: map[string]bool{}, groups: map[int64]bool{}, assign: assign, defGroup: defGroup, groupsKnown: known}
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
		g, ok := st.assign[agent]
		if !ok {
			g = st.defGroup
		}
		if st.groups[g] {
			return skipGroup
		}
	}
	return ""
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
}

// refreshPolicy rozpatruje zlecenia zmian z panelu i odświeża politykę
// oraz przypisania agentów do grup. Przy błędzie bazy zostaje poprzednia.
func refreshPolicy(ctx context.Context, s PolicyStore, pol *Policy, grace time.Duration, log *slog.Logger, m *metrics.Archiver) {
	changed, cur, err := s.ProcessPolicyChanges(ctx, pol.Bounds, grace, time.Now().UTC())
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("rozpatrzenie zmian polityki nieudane – obowiązuje poprzednia", "err", err)
		}
		return
	}
	for _, c := range changed {
		args := []any{"change", c.ID, "by", c.RequestedBy, "enabled", c.Enabled, "retention_days", c.RetentionDays,
			"excluded_groups", c.ExcludedGroups, "excluded_agents", c.ExcludedAgents, "reason", c.Reason}
		switch c.Status {
		case urd.PolicyApplied:
			log.Warn("polityka archiwum zmieniona", args...)
		case urd.PolicyScheduled:
			log.Warn("zaplanowano osłabienie polityki archiwum", append(args, "weakening", c.Weakening, "effective_at", c.EffectiveAt)...)
		case urd.PolicyRejected:
			log.Warn("zmiana polityki archiwum odrzucona", append(args, "error", c.Error)...)
		default:
			log.Info("zlecenie zmiany polityki zamknięte", "change", c.ID, "status", c.Status)
		}
	}
	assign, def, known, err := s.SourceGroups(ctx)
	if err != nil {
		log.Warn("odczyt grup agentów nieudany – wykluczenia grup chwilowo nie działają", "err", err)
	} else if !known && len(cur.ExcludedGroups) > 0 {
		log.Warn("brak dostępu do grup agentów (tabele panelu) – wykluczenia grup nie działają, archiwum zbiera wszystko")
	}
	pol.Set(cur, assign, def, known && err == nil)

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
