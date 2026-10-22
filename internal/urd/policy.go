// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Policy to polityka archiwum ustawiana w panelu.
type Policy struct {
	Enabled        bool      `json:"enabled"`
	RetentionDays  int       `json:"retention_days"`
	ExcludedGroups []int64   `json:"excluded_groups"`
	ExcludedAgents []string  `json:"excluded_agents"`
	ChangeID       *int64    `json:"change_id,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      string    `json:"updated_by"`
}

// Stany zlecenia zmiany polityki.
const (
	PolicyPending    = "pending"    // czeka na archiwizator (do minuty)
	PolicyScheduled  = "scheduled"  // osłabienie – wejdzie w życie po karencji
	PolicyApplied    = "applied"    // obowiązuje (albo obowiązywało)
	PolicyRejected   = "rejected"   // niezgodne z granicami z konfiguracji serwera
	PolicyCancelled  = "cancelled"  // anulowane w panelu przed wejściem w życie
	PolicySuperseded = "superseded" // zastąpione nowszym zleceniem
)

// Rodzaje osłabienia polityki (pole weakening).
const (
	WeakenDisable   = "disable"   // wyłączenie archiwizacji
	WeakenRetention = "retention" // krótsza retencja
	WeakenGroups    = "groups"    // nowe grupy wyłączone z archiwum
	WeakenAgents    = "agents"    // nowi agenci wyłączeni z archiwum
)

// PolicyChange to zlecenie zmiany polityki – pełna docelowa polityka
// (nie różnica), więc nowsze zlecenie zastępuje starsze.
type PolicyChange struct {
	ID             int64      `json:"id"`
	RequestedAt    time.Time  `json:"requested_at"`
	RequestedBy    string     `json:"requested_by"`
	Reason         string     `json:"reason"`
	Enabled        bool       `json:"enabled"`
	RetentionDays  int        `json:"retention_days"`
	ExcludedGroups []int64    `json:"excluded_groups"`
	ExcludedAgents []string   `json:"excluded_agents"`
	Reauth         bool       `json:"reauth"`
	Status         string     `json:"status"`
	Weakening      []string   `json:"weakening"`
	EffectiveAt    *time.Time `json:"effective_at,omitempty"`
	AppliedAt      *time.Time `json:"applied_at,omitempty"`
	CancelledAt    *time.Time `json:"cancelled_at,omitempty"`
	CancelledBy    string     `json:"cancelled_by,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// Target zwraca politykę, którą zlecenie ustawia.
func (c PolicyChange) Target() Policy {
	return Policy{Enabled: c.Enabled, RetentionDays: c.RetentionDays, ExcludedGroups: c.ExcludedGroups, ExcludedAgents: c.ExcludedAgents}
}

// PolicyBounds to granice retencji z konfiguracji serwera.
type PolicyBounds struct {
	MinRetentionDays int
	MaxRetentionDays int
}

// Check sprawdza retencję względem granic.
func (b PolicyBounds) Check(days int) error {
	if b.MinRetentionDays > 0 && days < b.MinRetentionDays {
		return fmt.Errorf("retencja %d dni jest krótsza niż minimum %d dni z konfiguracji serwera", days, b.MinRetentionDays)
	}
	if b.MaxRetentionDays > 0 && days > b.MaxRetentionDays {
		return fmt.Errorf("retencja %d dni jest dłuższa niż maksimum %d dni z konfiguracji serwera", days, b.MaxRetentionDays)
	}
	return nil
}

// Weakening zwraca, czym polityka next osłabia cur (pusta lista = zmiana
// wzmacnia albo nie zmienia ochrony i może wejść w życie od razu).
func Weakening(cur, next Policy) []string {
	w := []string{}
	if cur.Enabled && !next.Enabled {
		w = append(w, WeakenDisable)
	}
	if next.RetentionDays < cur.RetentionDays {
		w = append(w, WeakenRetention)
	}
	for _, g := range next.ExcludedGroups {
		if !slices.Contains(cur.ExcludedGroups, g) {
			w = append(w, WeakenGroups)
			break
		}
	}
	for _, a := range next.ExcludedAgents {
		if !slices.Contains(cur.ExcludedAgents, a) {
			w = append(w, WeakenAgents)
			break
		}
	}
	return w
}

// ErrNoPolicy: polityka jeszcze nie istnieje (archiwizator jej nie założył).
var ErrNoPolicy = errors.New("polityka archiwum nie jest jeszcze zapisana – archiwizator zakłada ją przy starcie")

// ErrPolicyChangeClosed: zlecenia nie można już anulować.
var ErrPolicyChangeClosed = errors.New("zlecenie już weszło w życie albo zostało zamknięte")

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func scanPolicy(r pgx.Row) (Policy, error) {
	var p Policy
	err := r.Scan(&p.Enabled, &p.RetentionDays, &p.ExcludedGroups, &p.ExcludedAgents, &p.ChangeID, &p.UpdatedAt, &p.UpdatedBy)
	p.ExcludedGroups, p.ExcludedAgents = nonNil(p.ExcludedGroups), nonNil(p.ExcludedAgents)
	return p, err
}

const policyCols = `enabled, retention_days, excluded_groups, excluded_agents, change_id, updated_at, updated_by`

const changeCols = `id, requested_at, requested_by, reason, enabled, retention_days, excluded_groups, excluded_agents,
	reauth, status, weakening, effective_at, applied_at, cancelled_at, coalesce(cancelled_by, ''), error`

func scanChange(r pgx.Row) (PolicyChange, error) {
	var c PolicyChange
	err := r.Scan(&c.ID, &c.RequestedAt, &c.RequestedBy, &c.Reason, &c.Enabled, &c.RetentionDays, &c.ExcludedGroups,
		&c.ExcludedAgents, &c.Reauth, &c.Status, &c.Weakening, &c.EffectiveAt, &c.AppliedAt, &c.CancelledAt, &c.CancelledBy, &c.Error)
	c.ExcludedGroups, c.ExcludedAgents, c.Weakening = nonNil(c.ExcludedGroups), nonNil(c.ExcludedAgents), nonNil(c.Weakening)
	return c, err
}

// Policy zwraca obowiązującą politykę.
func (p *PG) Policy(ctx context.Context) (Policy, error) {
	pol, err := scanPolicy(p.pool.QueryRow(ctx, `SELECT `+policyCols+` FROM urd.policy WHERE id = 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return pol, ErrNoPolicy
	}
	return pol, notConfigured(err)
}

// InitPolicy zakłada politykę przy pierwszym starcie archiwizatora (wartości
// z konfiguracji serwera); istniejącej nie zmienia. Zwraca obowiązującą.
func (p *PG) InitPolicy(ctx context.Context, initial Policy) (Policy, bool, error) {
	tag, err := p.pool.Exec(ctx, `INSERT INTO urd.policy (id, enabled, retention_days, excluded_groups, excluded_agents, updated_at, updated_by)
		VALUES (1, $1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		initial.Enabled, initial.RetentionDays, nonNil(initial.ExcludedGroups), nonNil(initial.ExcludedAgents),
		initial.UpdatedAt, initial.UpdatedBy)
	if err != nil {
		return initial, false, err
	}
	pol, err := p.Policy(ctx)
	return pol, tag.RowsAffected() == 1, err
}

// CreatePolicyChange składa zlecenie zmiany polityki (panel).
func (p *PG) CreatePolicyChange(ctx context.Context, c PolicyChange) (PolicyChange, error) {
	out, err := scanChange(p.pool.QueryRow(ctx, `INSERT INTO urd.policy_changes
		(requested_by, reason, enabled, retention_days, excluded_groups, excluded_agents, reauth)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+changeCols,
		c.RequestedBy, c.Reason, c.Enabled, c.RetentionDays, nonNil(c.ExcludedGroups), nonNil(c.ExcludedAgents), c.Reauth))
	return out, notConfigured(err)
}

// PolicyChanges zwraca ostatnie zlecenia zmian (najnowsze pierwsze).
func (p *PG) PolicyChanges(ctx context.Context, limit int) ([]PolicyChange, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+changeCols+` FROM urd.policy_changes ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyChange, error) { return scanChange(r) })
}

// CancelPolicyChange anuluje zlecenie, które jeszcze nie weszło w życie (panel).
// Archiwizator zamyka je przy najbliższym przeglądzie zleceń.
func (p *PG) CancelPolicyChange(ctx context.Context, id int64, by string, at time.Time) (PolicyChange, error) {
	c, err := scanChange(p.pool.QueryRow(ctx, `UPDATE urd.policy_changes SET cancelled_at = $2, cancelled_by = $3
		WHERE id = $1 AND status IN ('pending', 'scheduled') AND cancelled_at IS NULL RETURNING `+changeCols, id, at, by))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrPolicyChangeClosed
	}
	return c, notConfigured(err)
}

// ProcessPolicyChanges rozpatruje otwarte zlecenia (archiwizator, co minutę):
//
//   - anulowane w panelu są zamykane,
//   - obowiązuje najnowsze zlecenie, wcześniejsze otwarte są zastępowane,
//   - retencja spoza granic – odrzucenie,
//   - wzmocnienie wchodzi w życie od razu, osłabienie po karencji grace
//     liczonej od chwili, gdy archiwizator zobaczył zlecenie (od tej chwili
//     świeci też alert).
//
// Zwraca zlecenia, których stan się zmienił, i obowiązującą politykę.
func (p *PG) ProcessPolicyChanges(ctx context.Context, b PolicyBounds, grace time.Duration, now time.Time) ([]PolicyChange, Policy, error) {
	var changed []PolicyChange
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, Policy{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
	cur, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM urd.policy WHERE id = 1 FOR UPDATE`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, cur, ErrNoPolicy
	}
	if err != nil {
		return nil, cur, err
	}
	rows, err := tx.Query(ctx, `SELECT `+changeCols+` FROM urd.policy_changes
		WHERE status IN ('pending', 'scheduled') ORDER BY id FOR UPDATE`)
	if err != nil {
		return nil, cur, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyChange, error) { return scanChange(r) })
	if err != nil {
		return nil, cur, err
	}
	var open []PolicyChange
	for _, c := range all {
		if c.CancelledAt != nil {
			c.Status = PolicyCancelled
			changed = append(changed, c)
		} else {
			open = append(open, c)
		}
	}
	if len(open) > 0 {
		for _, c := range open[:len(open)-1] {
			c.Status = PolicySuperseded
			changed = append(changed, c)
		}
		c := open[len(open)-1]
		before := c.Status
		apply := false
		if err := b.Check(c.RetentionDays); err != nil {
			c.Status, c.Error = PolicyRejected, err.Error()
		} else if c.Status == PolicyPending {
			c.Weakening = Weakening(cur, c.Target())
			if len(c.Weakening) == 0 || grace <= 0 {
				apply = true
			} else {
				at := now.Add(grace)
				c.Status, c.EffectiveAt = PolicyScheduled, &at
			}
		} else if c.EffectiveAt != nil && !c.EffectiveAt.After(now) {
			apply = true
		}
		if apply {
			c.Status, c.AppliedAt = PolicyApplied, &now
			if c.EffectiveAt == nil {
				c.EffectiveAt = &now
			}
			if _, err := tx.Exec(ctx, `UPDATE urd.policy SET enabled = $1, retention_days = $2, excluded_groups = $3,
				excluded_agents = $4, change_id = $5, updated_at = $6, updated_by = $7 WHERE id = 1`,
				c.Enabled, c.RetentionDays, c.ExcludedGroups, c.ExcludedAgents, c.ID, now, c.RequestedBy); err != nil {
				return nil, cur, err
			}
			cur = c.Target()
			id := c.ID
			cur.ChangeID, cur.UpdatedAt, cur.UpdatedBy = &id, now, c.RequestedBy
		}
		if c.Status != before {
			changed = append(changed, c)
		}
	}
	for _, c := range changed {
		if _, err := tx.Exec(ctx, `UPDATE urd.policy_changes SET status = $2, weakening = $3, effective_at = $4,
			applied_at = $5, error = $6 WHERE id = $1`, c.ID, c.Status, c.Weakening, c.EffectiveAt, c.AppliedAt, c.Error); err != nil {
			return nil, cur, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, cur, err
	}
	return changed, cur, nil
}

// ScheduledChange zwraca zaplanowane osłabienie polityki (jeśli jest).
func (p *PG) ScheduledChange(ctx context.Context) (*PolicyChange, error) {
	c, err := scanChange(p.pool.QueryRow(ctx, `SELECT `+changeCols+` FROM urd.policy_changes
		WHERE status = 'scheduled' AND cancelled_at IS NULL ORDER BY id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, notConfigured(err)
	}
	return &c, nil
}

// SourceGroups zwraca przypisania agentów do grup (tabele panelu w schemacie
// public; archiwizator ma do nich prawo odczytu) i grupę domyślną – dla
// agentów bez przypisania. ok = false, gdy tabel nie ma albo brak uprawnień:
// wtedy wykluczenia grup nie działają (archiwum zbiera wszystko).
func (p *PG) SourceGroups(ctx context.Context) (assign map[string]int64, defaultGroup int64, ok bool, err error) {
	if err := p.pool.QueryRow(ctx, `SELECT coalesce((SELECT id FROM public.agent_groups WHERE is_default LIMIT 1), 0)`).
		Scan(&defaultGroup); err != nil {
		if notConfigured(err) == ErrNotConfigured || isPermission(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	rows, err := p.pool.Query(ctx, `SELECT agent_id, group_id FROM public.agent_assignments`)
	if err != nil {
		if notConfigured(err) == ErrNotConfigured || isPermission(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	defer rows.Close()
	assign = map[string]int64{}
	for rows.Next() {
		var a string
		var g int64
		if err := rows.Scan(&a, &g); err != nil {
			return nil, 0, false, err
		}
		assign[a] = g
	}
	return assign, defaultGroup, true, rows.Err()
}

// GroupMembership zwraca, od kiedy agenci są w obecnych grupach (agent →
// grupa i czas wejścia), według obserwacji archiwizatora.
func (p *PG) GroupMembership(ctx context.Context) (map[string]Membership, error) {
	rows, err := p.pool.Query(ctx, `SELECT agent_id, group_id, since FROM urd.group_membership`)
	if err != nil {
		return nil, notConfigured(err)
	}
	defer rows.Close()
	out := map[string]Membership{}
	for rows.Next() {
		var a string
		var m Membership
		if err := rows.Scan(&a, &m.Group, &m.Since); err != nil {
			return nil, err
		}
		out[a] = m
	}
	return out, rows.Err()
}

// Membership to obecna grupa agenta i czas wejścia do niej.
type Membership struct {
	Group int64     `json:"group"`
	Since time.Time `json:"since"`
}

// SaveGroupMembership zapisuje zmiany przynależności (archiwizator).
func (p *PG) SaveGroupMembership(ctx context.Context, changed map[string]Membership) error {
	if len(changed) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for a, m := range changed {
		b.Queue(`INSERT INTO urd.group_membership (agent_id, group_id, since) VALUES ($1, $2, $3)
			ON CONFLICT (agent_id) DO UPDATE SET group_id = $2, since = $3`, a, m.Group, m.Since)
	}
	return p.pool.SendBatch(ctx, b).Close()
}

// ManifestHashes zwraca SHA-256 manifestów o podanych numerach (panel
// porównuje z nimi kotwice wysłane poza system).
func (p *PG) ManifestHashes(ctx context.Context, seqs []int64) (map[int64]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT seq, sha256 FROM urd.manifests WHERE seq = ANY($1)`, seqs)
	if err != nil {
		return nil, notConfigured(err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var s int64
		var h string
		if err := rows.Scan(&s, &h); err != nil {
			return nil, err
		}
		out[s] = h
	}
	return out, rows.Err()
}
