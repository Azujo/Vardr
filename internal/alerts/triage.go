// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Activity to wpis osi czasu alertu.
type Activity struct {
	ID      int64          `json:"id"`
	At      time.Time      `json:"at"`
	Actor   string         `json:"actor"`
	Kind    string         `json:"kind"` // note | status | assign
	Text    string         `json:"text,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func addActivity(ctx context.Context, tx pgx.Tx, id int64, at time.Time, actor, kind, text string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.alert_activity (alert_id, at, actor, kind, text, details)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, at, actor, kind, text, details)
	return err
}

// SetStatus zmienia stan alertu (panel): open, acknowledged albo closed
// (z powodem); zmiana trafia na oś czasu.
func (p *PG) SetStatus(ctx context.Context, id int64, status, by, reason string, now time.Time) (Alert, error) {
	out, err := p.SetStatusMany(ctx, []int64{id}, status, by, reason, now)
	if err != nil {
		return Alert{}, err
	}
	if len(out) == 0 { // już w tym stanie albo nie ma takiego alertu
		return p.Alert(ctx, id)
	}
	return out[0], nil
}

// SetStatusMany zmienia stan wielu alertów w jednej transakcji (pomija
// alerty, które już mają ten stan). Zwraca zmienione alerty.
func (p *PG) SetStatusMany(ctx context.Context, ids []int64, status, by, reason string, now time.Time) ([]Alert, error) {
	var closedAt *time.Time
	var closedBy, closeReason *string
	if status == "closed" {
		closedAt, closedBy, closeReason = &now, &by, &reason
	}
	var out []Alert
	err := p.retryTx(ctx, func(tx pgx.Tx) error {
		out = nil
		for _, id := range ids {
			var prev string
			err := tx.QueryRow(ctx, `SELECT status FROM gjallarhorn.alerts WHERE id = $1 FOR UPDATE`, id).Scan(&prev)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if prev == status {
				continue
			}
			a, err := scanAlert(tx.QueryRow(ctx, `UPDATE gjallarhorn.alerts SET status = $2, closed_at = $3, closed_by = $4,
				close_reason = $5, updated_at = $6 WHERE id = $1 RETURNING `+alertCols, id, status, closedAt, closedBy, closeReason, now))
			if err != nil {
				return err
			}
			if err := addActivity(ctx, tx, id, now, by, "status", reason, map[string]any{"from": prev, "to": status}); err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	})
	return out, notConfigured(err)
}

// Assign przypisuje alert analitykowi (pusty = bez przypisania).
func (p *PG) Assign(ctx context.Context, id int64, assignee, by string, now time.Time) (Alert, error) {
	var a Alert
	err := p.retryTx(ctx, func(tx pgx.Tx) error {
		var prev string
		err := tx.QueryRow(ctx, `SELECT assignee FROM gjallarhorn.alerts WHERE id = $1 FOR UPDATE`, id).Scan(&prev)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		a, err = scanAlert(tx.QueryRow(ctx, `UPDATE gjallarhorn.alerts SET assignee = $2, updated_at = $3 WHERE id = $1
			RETURNING `+alertCols, id, assignee, now))
		if err != nil || prev == assignee {
			return err
		}
		return addActivity(ctx, tx, id, now, by, "assign", "", map[string]any{"from": prev, "to": assignee})
	})
	return a, notConfigured(err)
}

// retryTx wykonuje transakcję, ponawiając ją (do 3 razy) po zakleszczeniu
// z równoległym zapisem detektora (dopisanie trafień do tego samego alertu).
func (p *PG) retryTx(ctx context.Context, fn func(pgx.Tx) error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = pgx.BeginFunc(ctx, p.pool, fn)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || (pg.Code != "40P01" && pg.Code != "40001") {
			return err
		}
		time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
	}
	return err
}

// AddNote dopisuje notatkę analityka do osi czasu alertu.
func (p *PG) AddNote(ctx context.Context, id int64, by, text string, now time.Time) error {
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM gjallarhorn.alerts WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return addActivity(ctx, tx, id, now, by, "note", text, nil)
	})
	return notConfigured(err)
}

// Activity zwraca oś czasu alertu (od najstarszych).
func (p *PG) Activity(ctx context.Context, id int64) ([]Activity, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, at, actor, kind, text, details FROM gjallarhorn.alert_activity
		WHERE alert_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Activity])
}

// Related zwraca alerty z tego samego komputera, konta albo osoby
// (user.identity – to samo konto w AD, Entra ID i na VPN) w promieniu
// window od pierwszego zdarzenia alertu (bez niego samego).
func (p *PG) Related(ctx context.Context, a Alert, window time.Duration, limit int) ([]Alert, error) {
	if a.HostName == "" && a.UserName == "" && a.UserIdentity == "" {
		return []Alert{}, nil
	}
	rows, err := p.pool.Query(ctx, `SELECT `+alertCols+` FROM gjallarhorn.alerts
		WHERE id <> $1 AND first_seen BETWEEN $4 AND $5
		AND (($2 <> '' AND lower(host_name) = lower($2)) OR ($3 <> '' AND lower(user_name) = lower($3))
			OR ($7 <> '' AND user_identity = $7))
		ORDER BY first_seen DESC LIMIT $6`, a.ID, a.HostName, a.UserName, a.FirstSeen.Add(-window), a.LastSeen.Add(window), limit,
		a.UserIdentity)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) { return scanAlert(r) })
}
