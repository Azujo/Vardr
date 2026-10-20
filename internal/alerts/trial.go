package alerts

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// TrialHit to trafienia reguły próbnej w jednej godzinie na jednym
// komputerze (detektor zlicza je w pamięci i dopisuje co 30 s).
type TrialHit struct {
	RuleID        string
	Hour          time.Time
	Host          string
	Hits          int64
	First, Last   time.Time
	SampleEventID string // ostatnie trafienie (podgląd w Mímirze)
	SampleSummary string
}

// RecordTrial dopisuje trafienia reguł próbnych (sumuje z zapisanymi).
// Trafienia reguł, które w międzyczasie wyszły z próby, są pomijane.
func (p *PG) RecordTrial(ctx context.Context, hits []TrialHit) error {
	if len(hits) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, h := range hits {
		b.Queue(`INSERT INTO gjallarhorn.rule_trial_hits (rule_id, hour, host_name, hits, first_at, last_at, sample_event_id, sample_summary)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8 WHERE EXISTS (SELECT FROM gjallarhorn.rule_overrides WHERE rule_id = $1 AND trial)
			ON CONFLICT (rule_id, hour, host_name) DO UPDATE SET hits = rule_trial_hits.hits + EXCLUDED.hits,
			first_at = LEAST(rule_trial_hits.first_at, EXCLUDED.first_at),
			last_at = GREATEST(rule_trial_hits.last_at, EXCLUDED.last_at),
			sample_event_id = CASE WHEN EXCLUDED.last_at >= rule_trial_hits.last_at THEN EXCLUDED.sample_event_id ELSE rule_trial_hits.sample_event_id END,
			sample_summary = CASE WHEN EXCLUDED.last_at >= rule_trial_hits.last_at THEN EXCLUDED.sample_summary ELSE rule_trial_hits.sample_summary END`,
			h.RuleID, h.Hour, h.Host, h.Hits, h.First, h.Last, h.SampleEventID, h.SampleSummary)
	}
	return notConfigured(p.pool.SendBatch(ctx, b).Close())
}

// PruneTrial usuwa trafienia prób starsze niż before.
func (p *PG) PruneTrial(ctx context.Context, before time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.rule_trial_hits WHERE hour < $1`, before)
	return tag.RowsAffected(), notConfigured(err)
}

// TrialDay to trafienia reguły próbnej jednego dnia (UTC).
type TrialDay struct {
	Day  time.Time `json:"day"`
	Hits int64     `json:"hits"`
}

// TrialHost to trafienia reguły próbnej na jednym komputerze.
type TrialHost struct {
	Host string `json:"host"`
	Hits int64  `json:"hits"`
}

// TrialStat to wynik próby reguły od jej rozpoczęcia.
type TrialStat struct {
	RuleID        string      `json:"rule_id"`
	Since         time.Time   `json:"since"`
	ChangedBy     string      `json:"changed_by"`
	Reason        string      `json:"reason"`
	Hits          int64       `json:"hits"`
	Hosts         int         `json:"hosts"`
	Days          []TrialDay  `json:"days"`
	TopHosts      []TrialHost `json:"top_hosts"`
	LastAt        *time.Time  `json:"last_at,omitempty"`
	SampleEventID string      `json:"sample_event_id,omitempty"`
	SampleSummary string      `json:"sample_summary,omitempty"`
}

// TrialStats zwraca wyniki wszystkich reguł w trybie próbnym (także bez
// trafień), z trafieniami od początku próby.
func (p *PG) TrialStats(ctx context.Context) ([]TrialStat, error) {
	rows, err := p.pool.Query(ctx, `SELECT rule_id, changed_at, changed_by, reason FROM gjallarhorn.rule_overrides
		WHERE trial ORDER BY rule_id`)
	if err != nil {
		return nil, notConfigured(err)
	}
	stats := map[string]*TrialStat{}
	var order []string
	for rows.Next() {
		var s TrialStat
		if err := rows.Scan(&s.RuleID, &s.Since, &s.ChangedBy, &s.Reason); err != nil {
			rows.Close()
			return nil, err
		}
		s.Days, s.TopHosts = []TrialDay{}, []TrialHost{}
		stats[s.RuleID] = &s
		order = append(order, s.RuleID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	const scope = `FROM gjallarhorn.rule_trial_hits h JOIN gjallarhorn.rule_overrides o ON o.rule_id = h.rule_id AND o.trial
		WHERE h.hour >= date_trunc('hour', o.changed_at)`
	// Dni.
	rows, err = p.pool.Query(ctx, `SELECT h.rule_id, date_trunc('day', h.hour), sum(h.hits) `+scope+` GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var d TrialDay
		if err := rows.Scan(&id, &d.Day, &d.Hits); err != nil {
			rows.Close()
			return nil, err
		}
		if s := stats[id]; s != nil {
			s.Days = append(s.Days, d)
			s.Hits += d.Hits
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Komputery.
	rows, err = p.pool.Query(ctx, `SELECT h.rule_id, h.host_name, sum(h.hits) `+scope+` GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var x TrialHost
		if err := rows.Scan(&id, &x.Host, &x.Hits); err != nil {
			rows.Close()
			return nil, err
		}
		if s := stats[id]; s != nil {
			s.Hosts++
			s.TopHosts = append(s.TopHosts, x)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Ostatnie trafienie (przykład).
	rows, err = p.pool.Query(ctx, `SELECT DISTINCT ON (h.rule_id) h.rule_id, h.last_at, h.sample_event_id, h.sample_summary `+scope+`
		ORDER BY h.rule_id, h.last_at DESC`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, ev, sum string
		var at time.Time
		if err := rows.Scan(&id, &at, &ev, &sum); err != nil {
			rows.Close()
			return nil, err
		}
		if s := stats[id]; s != nil {
			s.LastAt, s.SampleEventID, s.SampleSummary = &at, ev, sum
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TrialStat, 0, len(order))
	for _, id := range order {
		s := stats[id]
		sort.Slice(s.TopHosts, func(i, j int) bool { return s.TopHosts[i].Hits > s.TopHosts[j].Hits })
		if len(s.TopHosts) > 5 {
			s.TopHosts = s.TopHosts[:5]
		}
		out = append(out, *s)
	}
	return out, nil
}
