// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RuleException to wyjątek reguły (wersja 1.5.3): zdarzenia spełniające
// Match nie trafiają w regułę. Po ExpiresAt detektor go pomija.
type RuleException struct {
	ID         int64          `json:"id"`
	RuleID     string         `json:"rule_id"`
	Match      map[string]any `json:"match"`
	Reason     string         `json:"reason"`
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	AIProposed bool           `json:"ai_proposed"`
}

const exceptionCols = `id, rule_id, match, reason, created_by, created_at, expires_at, ai_proposed`

// ActiveExceptions zwraca obowiązujące (niewygasłe) wyjątki i ich podpis –
// zmiana podpisu (nowy, usunięty albo wygasły wyjątek) przeładowuje reguły.
func (p *PG) ActiveExceptions(ctx context.Context, now time.Time) ([]RuleException, string, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+exceptionCols+` FROM gjallarhorn.rule_exceptions
		WHERE expires_at IS NULL OR expires_at > $1 ORDER BY id`, now)
	if err != nil {
		return nil, "", notConfigured(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RuleException])
	if err != nil {
		return nil, "", err
	}
	var sig strings.Builder
	for _, e := range out {
		fmt.Fprintf(&sig, "%d;", e.ID)
	}
	return out, sig.String(), nil
}

// RuleExceptions zwraca wyjątki reguły (także wygasłe – do przeglądu).
func (p *PG) RuleExceptions(ctx context.Context, rule string) ([]RuleException, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+exceptionCols+` FROM gjallarhorn.rule_exceptions
		WHERE rule_id = $1 ORDER BY id DESC`, rule)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RuleException])
}

// ExceptionCounts zwraca liczbę obowiązujących wyjątków każdej reguły.
func (p *PG) ExceptionCounts(ctx context.Context, now time.Time) (map[string]int, error) {
	rows, err := p.pool.Query(ctx, `SELECT rule_id, count(*) FROM gjallarhorn.rule_exceptions
		WHERE expires_at IS NULL OR expires_at > $1 GROUP BY rule_id`, now)
	if err != nil {
		return nil, notConfigured(err)
	}
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = n
	}
	rows.Close()
	return out, rows.Err()
}

// RuleException zwraca jeden wyjątek.
func (p *PG) RuleException(ctx context.Context, id int64) (RuleException, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+exceptionCols+` FROM gjallarhorn.rule_exceptions WHERE id = $1`, id)
	if err != nil {
		return RuleException{}, notConfigured(err)
	}
	e, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[RuleException])
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// AddRuleException zapisuje wyjątek i zwraca jego id.
func (p *PG) AddRuleException(ctx context.Context, e RuleException) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO gjallarhorn.rule_exceptions (rule_id, match, reason, created_by, created_at,
		expires_at, ai_proposed) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		e.RuleID, e.Match, e.Reason, e.CreatedBy, e.CreatedAt, e.ExpiresAt, e.AIProposed).Scan(&id)
	return id, notConfigured(err)
}

// DeleteRuleException usuwa wyjątek (reguła znów wykrywa te zdarzenia).
func (p *PG) DeleteRuleException(ctx context.Context, id int64) (bool, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.rule_exceptions WHERE id = $1`, id)
	return tag.RowsAffected() > 0, notConfigured(err)
}
