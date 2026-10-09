package alerts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentBeat to ostatni heartbeat agenta i próg alarmu jego grupy
// (tabele panelu w schemacie public – detektor ma do nich prawo odczytu).
type AgentBeat struct {
	ID         string
	Host       string
	IP         string
	Version    string
	Group      string
	LastSeen   time.Time
	AlertAfter time.Duration // 0 = grupa bez alarmu
	// NotifyReturn: grupa chce powiadomienia także o powrocie agenta.
	NotifyReturn bool
}

// AgentBeats zwraca agentów z progiem alarmu grupy. Pomija agentów
// wycofanych (wszystkie certyfikaty unieważnione).
func (p *PG) AgentBeats(ctx context.Context) ([]AgentBeat, error) {
	rows, err := p.pool.Query(ctx, `SELECT a.id, a.hostname, a.remote_ip, a.version, a.last_seen, g.name,
		coalesce((g.limits->>'heartbeat_alert_min')::int, 0), coalesce((g.limits->>'heartbeat_notify_return')::boolean, false)
		FROM public.agents a
		LEFT JOIN public.agent_assignments s ON s.agent_id = a.id
		JOIN public.agent_groups g ON g.id = coalesce(s.group_id, (SELECT id FROM public.agent_groups WHERE is_default))
		WHERE NOT (EXISTS (SELECT 1 FROM public.agent_certs c WHERE c.agent_id = a.id)
			AND NOT EXISTS (SELECT 1 FROM public.agent_certs c WHERE c.agent_id = a.id AND c.revoked_at IS NULL))`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AgentBeat, error) {
		var b AgentBeat
		var min int
		err := r.Scan(&b.ID, &b.Host, &b.IP, &b.Version, &b.LastSeen, &b.Group, &min, &b.NotifyReturn)
		b.AlertAfter = time.Duration(min) * time.Minute
		return b, err
	})
}

// CloseOpen zamyka otwarte alerty reguły z kluczem zaczynającym się od
// groupKey (np. agent znów wysyła heartbeat); notify – powiadomienie
// o rozwiązaniu (outbox, ta sama transakcja). Zwraca liczbę zamkniętych.
func (p *PG) CloseOpen(ctx context.Context, rule, groupKey, reason string, notify bool, now time.Time) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE gjallarhorn.alerts SET status = 'closed', closed_at = $4, closed_by = 'system',
			close_reason = $3, updated_at = $4 WHERE rule_id = $1 AND starts_with(group_key, $2) AND status <> 'closed'
			RETURNING id`, rule, groupKey, reason, now)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		n = int64(len(ids))
		if notify {
			for _, id := range ids {
				if _, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.outbox (alert_id, kind) VALUES ($1, 'resolved')`, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return n, err
}

// OpenAgents zwraca agentów z otwartymi alertami reguły.
func (p *PG) OpenAgents(ctx context.Context, rule string) (map[string]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT DISTINCT agent_id FROM gjallarhorn.alerts WHERE rule_id = $1 AND status <> 'closed'`, rule)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, err
}
