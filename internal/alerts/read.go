package alerts

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Alert to alert dla panelu.
type Alert struct {
	ID           int64             `json:"id"`
	RuleID       string            `json:"rule_id"`
	RuleTitle    string            `json:"rule_title"`
	Level        string            `json:"level"`
	Engine       string            `json:"engine"`
	GroupKey     string            `json:"group_key"`
	GroupFields  map[string]string `json:"group_fields"`
	Status       string            `json:"status"`
	Hits         int               `json:"hits"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	AgentID      string            `json:"agent_id"`
	HostName     string            `json:"host_name"`
	UserName     string            `json:"user_name"`
	SourceIP     string            `json:"source_ip"`
	FirstEventID string            `json:"first_event_id"`
	Summary      string            `json:"summary"`
	Instructions string            `json:"instructions"`
	ClosedAt     *time.Time        `json:"closed_at,omitempty"`
	ClosedBy     string            `json:"closed_by,omitempty"`
	CloseReason  string            `json:"close_reason,omitempty"`
	Assignee     string            `json:"assignee,omitempty"`
}

const alertCols = `id, rule_id, rule_title, level, engine, group_key, group_fields, status, hits, first_seen, last_seen,
	created_at, updated_at, agent_id, host_name, user_name, source_ip, first_event_id, summary, instructions, closed_at,
	coalesce(closed_by, ''), coalesce(close_reason, ''), assignee`

func scanAlert(r pgx.Row) (Alert, error) {
	var a Alert
	err := r.Scan(&a.ID, &a.RuleID, &a.RuleTitle, &a.Level, &a.Engine, &a.GroupKey, &a.GroupFields, &a.Status, &a.Hits,
		&a.FirstSeen, &a.LastSeen, &a.CreatedAt, &a.UpdatedAt, &a.AgentID, &a.HostName, &a.UserName, &a.SourceIP,
		&a.FirstEventID, &a.Summary, &a.Instructions, &a.ClosedAt, &a.ClosedBy, &a.CloseReason, &a.Assignee)
	if a.GroupFields == nil {
		a.GroupFields = map[string]string{}
	}
	return a, err
}

// Filter to filtr listy alertów.
type Filter struct {
	Status   string // "" = wszystkie, open = otwarte i potwierdzone
	Level    string // najniższy poziom („high” = wysokie i krytyczne)
	RuleID   string
	Host     string // komputer (bez wielkości liter, fragment)
	User     string // konto (bez wielkości liter, fragment)
	Assignee string // login; "-" = bez przypisania
	Engine   string
	Text     string // fragment reguły, opisu, komputera albo konta
	Since    *time.Time
	Limit    int
	Before   int64 // stronicowanie: id < Before
}

var levelRank = `array_position(ARRAY['informational','low','medium','high','critical'], level)`

func (f Filter) where() (string, []any) {
	like := func(s string) string {
		r := []rune{}
		for _, c := range s {
			if c == '%' || c == '_' || c == '\\' {
				r = append(r, '\\')
			}
			r = append(r, c)
		}
		return "%" + string(r) + "%"
	}
	args := []any{f.Status, f.Level, f.RuleID, like(f.Host), like(f.User), f.Assignee, f.Engine, like(f.Text), f.Since}
	return `($1 = '' OR ($1 = 'open' AND status <> 'closed') OR status = $1)
		AND ($2 = '' OR ` + levelRank + ` >= array_position(ARRAY['informational','low','medium','high','critical'], $2))
		AND ($3 = '' OR rule_id = $3)
		AND ($4 = '%%' OR host_name ILIKE $4) AND ($5 = '%%' OR user_name ILIKE $5)
		AND ($6 = '' OR assignee = CASE WHEN $6 = '-' THEN '' ELSE $6 END)
		AND ($7 = '' OR engine = $7)
		AND ($8 = '%%' OR rule_title ILIKE $8 OR summary ILIKE $8 OR host_name ILIKE $8 OR user_name ILIKE $8)
		AND ($9::timestamptz IS NULL OR last_seen >= $9)`, args
}

// Alerts zwraca alerty (najnowsze pierwsze) i liczbę wszystkich pasujących.
func (p *PG) Alerts(ctx context.Context, f Filter) ([]Alert, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	where, args := f.where()
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM gjallarhorn.alerts WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, notConfigured(err)
	}
	q := `SELECT ` + alertCols + ` FROM gjallarhorn.alerts WHERE ` + where + ` AND ($10 = 0 OR id < $10) ORDER BY id DESC LIMIT $11`
	rows, err := p.pool.Query(ctx, q, append(args, f.Before, f.Limit)...)
	if err != nil {
		return nil, 0, notConfigured(err)
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) { return scanAlert(r) })
	return list, total, err
}

// Alert zwraca alert.
func (p *PG) Alert(ctx context.Context, id int64) (Alert, error) {
	a, err := scanAlert(p.pool.QueryRow(ctx, `SELECT `+alertCols+` FROM gjallarhorn.alerts WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, notConfigured(err)
}

// EventRef to zdarzenie przypisane do alertu.
type EventRef struct {
	EventID   string    `json:"event_id"`
	EventTime time.Time `json:"event_time"`
}

// AlertEvents zwraca zdarzenia alertu (najwyżej limit, najnowsze pierwsze).
func (p *PG) AlertEvents(ctx context.Context, id int64, limit int) ([]EventRef, error) {
	rows, err := p.pool.Query(ctx, `SELECT event_id, event_time FROM gjallarhorn.alert_events
		WHERE alert_id = $1 ORDER BY event_time DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EventRef])
}

// Summary to liczby alertów dla strony startowej i menu.
type Summary struct {
	Open     int            `json:"open"`
	ByLevel  map[string]int `json:"open_by_level"`
	Last24h  int            `json:"last_24h"`
	LastAt   *time.Time     `json:"last_at,omitempty"`
	Rules    int            `json:"rules"`
	RuleErrs int            `json:"rule_errors"`
}

// Summarize liczy otwarte alerty.
func (p *PG) Summarize(ctx context.Context, now time.Time) (Summary, error) {
	s := Summary{ByLevel: map[string]int{}}
	rows, err := p.pool.Query(ctx, `SELECT level, count(*) FROM gjallarhorn.alerts WHERE status <> 'closed' GROUP BY level`)
	if err != nil {
		return s, notConfigured(err)
	}
	for rows.Next() {
		var l string
		var n int
		if err := rows.Scan(&l, &n); err != nil {
			return s, err
		}
		s.ByLevel[l] = n
		s.Open += n
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_at > $1), max(created_at) FROM gjallarhorn.alerts`,
		now.Add(-24*time.Hour)).Scan(&s.Last24h, &s.LastAt); err != nil {
		return s, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM gjallarhorn.rules WHERE removed_at IS NULL AND enabled),
		(SELECT count(*) FROM gjallarhorn.rule_errors)`).Scan(&s.Rules, &s.RuleErrs); err != nil {
		return s, err
	}
	return s, nil
}

// Rules zwraca reguły (bez usuniętych) z liczbą otwartych alertów.
func (p *PG) Rules(ctx context.Context) ([]RuleInfo, []RuleError, error) {
	rows, err := p.pool.Query(ctx, `SELECT r.id, r.title, r.level, r.description, r.tags, r.file, r.source, r.mode, r.enabled,
		r.group_by, r.suppress_s, r.instructions, r.threshold, r.loaded_at, r.removed_at,
		(SELECT count(*) FROM gjallarhorn.alerts a WHERE a.rule_id = r.id AND a.status <> 'closed')
		FROM gjallarhorn.rules r WHERE r.removed_at IS NULL ORDER BY r.level DESC, r.title`)
	if err != nil {
		return nil, nil, notConfigured(err)
	}
	rules, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (RuleInfo, error) {
		var x RuleInfo
		err := r.Scan(&x.ID, &x.Title, &x.Level, &x.Description, &x.Tags, &x.File, &x.Source, &x.Mode, &x.Enabled,
			&x.GroupBy, &x.SuppressS, &x.Instructions, &x.Threshold, &x.LoadedAt, &x.RemovedAt, &x.OpenAlerts)
		return x, err
	})
	if err != nil {
		return nil, nil, err
	}
	rows, err = p.pool.Query(ctx, `SELECT file, error, seen_at FROM gjallarhorn.rule_errors ORDER BY file`)
	if err != nil {
		return nil, nil, err
	}
	errs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RuleError])
	return rules, errs, err
}

// Rule zwraca regułę (także usuniętą – alerty mogą się do niej odwoływać).
func (p *PG) Rule(ctx context.Context, id string) (RuleInfo, error) {
	var x RuleInfo
	err := p.pool.QueryRow(ctx, `SELECT id, title, level, description, tags, file, source, mode, enabled, group_by,
		suppress_s, instructions, threshold, loaded_at, removed_at FROM gjallarhorn.rules WHERE id = $1`, id).
		Scan(&x.ID, &x.Title, &x.Level, &x.Description, &x.Tags, &x.File, &x.Source, &x.Mode, &x.Enabled, &x.GroupBy,
			&x.SuppressS, &x.Instructions, &x.Threshold, &x.LoadedAt, &x.RemovedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return x, ErrNotFound
	}
	return x, notConfigured(err)
}

// Pending to powiadomienie czekające w outboxie.
type Pending struct {
	OutboxID int64
	Attempts int
	Alert    Alert
	Kind     string // new | resolved
}

// ClaimOutbox bierze do wysyłki powiadomienia, których termin minął.
// Rezerwacja przesuwa next_attempt_at, więc równoległy proces ich nie weźmie.
func (p *PG) ClaimOutbox(ctx context.Context, now time.Time, limit int) ([]Pending, error) {
	rows, err := p.pool.Query(ctx, `UPDATE gjallarhorn.outbox o SET next_attempt_at = $1 + interval '2 minutes'
		WHERE o.id IN (SELECT id FROM gjallarhorn.outbox WHERE sent_at IS NULL AND next_attempt_at <= $1
			ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED)
		RETURNING o.id, o.attempts, o.alert_id, o.kind`, now, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	type row struct {
		id       int64
		attempts int
		alert    int64
		kind     string
	}
	claimed, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.attempts, &x.alert, &x.kind)
		return x, err
	})
	if err != nil {
		return nil, err
	}
	// UPDATE … RETURNING nie gwarantuje kolejności – wysyłka w kolejności
	// outboxa (np. alert przed wiadomością o jego rozwiązaniu).
	sort.Slice(claimed, func(i, j int) bool { return claimed[i].id < claimed[j].id })
	out := make([]Pending, 0, len(claimed))
	for _, c := range claimed {
		a, err := p.Alert(ctx, c.alert)
		if err != nil {
			return nil, err
		}
		out = append(out, Pending{OutboxID: c.id, Attempts: c.attempts, Alert: a, Kind: c.kind})
	}
	return out, nil
}

// MarkSent oznacza wysłane powiadomienie.
func (p *PG) MarkSent(ctx context.Context, id int64, now time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE gjallarhorn.outbox SET sent_at = $2, attempts = attempts + 1, last_error = '' WHERE id = $1`, id, now)
	return err
}

// MarkFailed zapisuje błąd i termin kolejnej próby.
func (p *PG) MarkFailed(ctx context.Context, id int64, errMsg string, next time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE gjallarhorn.outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3
		WHERE id = $1`, id, errMsg, next)
	return err
}
