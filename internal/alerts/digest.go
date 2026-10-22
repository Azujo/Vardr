// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SentPerRule zwraca liczbę osobnych powiadomień o nowych alertach
// wysłanych od since, według reguły (limit burzy alertów).
func (p *PG) SentPerRule(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := p.pool.Query(ctx, `SELECT a.rule_id, count(*) FROM gjallarhorn.outbox o
		JOIN gjallarhorn.alerts a ON a.id = o.alert_id
		WHERE o.kind = 'new' AND NOT o.held AND o.sent_at >= $1 GROUP BY a.rule_id`, since)
	if err != nil {
		return nil, notConfigured(err)
	}
	out := map[string]int{}
	for rows.Next() {
		var r string
		var n int
		if err := rows.Scan(&r, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out[r] = n
	}
	rows.Close()
	return out, rows.Err()
}

// Hold wstrzymuje osobne powiadomienie (ponad limit) – alert trafi do
// wiadomości zbiorczej.
func (p *PG) Hold(ctx context.Context, outboxID int64, now time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE gjallarhorn.outbox SET held = true, sent_at = $2, last_error = '' WHERE id = $1`,
		outboxID, now)
	return err
}

// Digest to wiadomość zbiorcza dla reguły: wstrzymane alerty.
type Digest struct {
	RuleID    string
	RuleTitle string
	Levels    []string
	Count     int
	Hosts     []string // najwyżej kilka przykładów
	HostCount int
	First     time.Time // najstarsze wstrzymanie
	Upto      time.Time // najnowsze wstrzymanie (do oznaczenia)
}

// DueDigests zwraca reguły, których najstarszy wstrzymany alert czeka co
// najmniej od olderThan.
func (p *PG) DueDigests(ctx context.Context, olderThan time.Time) ([]Digest, error) {
	rows, err := p.pool.Query(ctx, `SELECT a.rule_id, max(a.rule_title), array_agg(DISTINCT a.level), count(*),
		(array_agg(DISTINCT a.host_name) FILTER (WHERE a.host_name <> ''))[1:5],
		count(DISTINCT a.host_name) FILTER (WHERE a.host_name <> ''), min(o.sent_at), max(o.sent_at)
		FROM gjallarhorn.outbox o JOIN gjallarhorn.alerts a ON a.id = o.alert_id
		WHERE o.held AND o.digest_sent_at IS NULL
		GROUP BY a.rule_id HAVING min(o.sent_at) <= $1 ORDER BY min(o.sent_at)`, olderThan)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Digest, error) {
		var d Digest
		err := r.Scan(&d.RuleID, &d.RuleTitle, &d.Levels, &d.Count, &d.Hosts, &d.HostCount, &d.First, &d.Upto)
		return d, err
	})
}

// MarkDigested oznacza wstrzymane alerty reguły (do upto) jako ujęte
// w wysłanej wiadomości zbiorczej.
func (p *PG) MarkDigested(ctx context.Context, rule string, upto, now time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE gjallarhorn.outbox o SET digest_sent_at = $3 FROM gjallarhorn.alerts a
		WHERE a.id = o.alert_id AND a.rule_id = $1 AND o.held AND o.digest_sent_at IS NULL AND o.sent_at <= $2`,
		rule, upto, now)
	return err
}
