// Package alerts to magazyn alertów Gjallarhorna w bazie Saga (schemat
// gjallarhorn): zapis trafień reguł przez detektor (idempotentny), odczyt
// i outbox powiadomień dla panelu.
package alerts

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	migrationLock = 0x476a616c5f6d6967 // "Gjal_mig"
	detectorLock  = 0x476a616c5f646574 // "Gjal_det"
)

// ErrNotConfigured: schemat gjallarhorn nie istnieje (detektor nie działał).
var ErrNotConfigured = errors.New("detekcja nie jest skonfigurowana")

// ErrNotFound: nie ma takiego alertu.
var ErrNotFound = errors.New("nie ma takiego alertu")

// PG to magazyn alertów.
type PG struct{ pool *pgxpool.Pool }

// Open łączy się z bazą.
func Open(ctx context.Context, url string) (*PG, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("adres bazy: %w", err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &PG{pool: pool}, nil
}

// New używa istniejącej puli (panel).
func New(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

func (p *PG) Close() { p.pool.Close() }

func notConfigured(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "42P01" || pg.Code == "3F000") {
		return ErrNotConfigured
	}
	return err
}

// Migrate tworzy lub aktualizuje schemat gjallarhorn (detektor).
func (p *PG) Migrate(ctx context.Context) (applied []string, err error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(migrationLock)); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", int64(migrationLock)) //nolint:errcheck
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'gjallarhorn')").Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		if _, err := conn.Exec(ctx, "CREATE SCHEMA gjallarhorn"); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS gjallarhorn.schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	rows, err := conn.Query(ctx, "SELECT version FROM gjallarhorn.schema_migrations")
	if err != nil {
		return nil, err
	}
	done, err := pgx.CollectRows(rows, pgx.RowTo[int])
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, path := range names {
		name := strings.TrimPrefix(path, "migrations/")
		num, _, _ := strings.Cut(name, "_")
		version, err := strconv.Atoi(num)
		if err != nil {
			return applied, fmt.Errorf("niepoprawna nazwa migracji %s", name)
		}
		if containsInt(done, version) {
			continue
		}
		sql, err := migrationFiles.ReadFile(path)
		if err != nil {
			return applied, err
		}
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO gjallarhorn.schema_migrations (version, name) VALUES ($1, $2)", version, name)
			return err
		}); err != nil {
			return applied, fmt.Errorf("migracja %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// LockDetector zajmuje blokadę jedynego detektora (stan progów i łączenie
// trafień muszą być w jednym miejscu). Druga kopia czeka.
func (p *PG) LockDetector(ctx context.Context) (func(), error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(detectorLock)); err != nil {
		conn.Release()
		return nil, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(detectorLock))
		conn.Release()
	}, nil
}

// RuleInfo to reguła zapisana dla panelu.
type RuleInfo struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Level        string     `json:"level"`
	Description  string     `json:"description"`
	Tags         []string   `json:"tags"`
	File         string     `json:"file"`
	Source       string     `json:"source,omitempty"`
	Mode         string     `json:"mode"`
	Enabled      bool       `json:"enabled"`      // obowiązujące (plik albo panel)
	FileEnabled  bool       `json:"file_enabled"` // ustawienie w pliku reguły
	Override     *Override  `json:"override,omitempty"`
	Version      int        `json:"version"`
	GroupBy      []string   `json:"group_by"`
	SuppressS    int        `json:"suppress_s"`
	Instructions string     `json:"instructions"`
	Threshold    *Threshold `json:"threshold,omitempty"`
	LoadedAt     time.Time  `json:"loaded_at"`
	RemovedAt    *time.Time `json:"removed_at,omitempty"`
	OpenAlerts   int        `json:"open_alerts"`
}

// Threshold to próg reguły progowej (opis dla panelu).
type Threshold struct {
	Count    int    `json:"count"`
	WindowS  int    `json:"window_s"`
	Distinct string `json:"distinct,omitempty"`
}

// RuleError to błąd wczytania pliku reguły.
type RuleError struct {
	File   string    `json:"file"`
	Error  string    `json:"error"`
	SeenAt time.Time `json:"seen_at"`
}

// SyncRules zapisuje wczytane reguły (usunięte oznacza removed_at) i błędy.
func (p *PG) SyncRules(ctx context.Context, rules []RuleInfo, errs []RuleError, now time.Time) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		ids := make([]string, 0, len(rules))
		for _, r := range rules {
			ids = append(ids, r.ID)
			if _, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.rules (id, title, level, description, tags, file, source, mode,
				enabled, group_by, suppress_s, instructions, threshold, loaded_at, removed_at, file_enabled)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULL, $15)
				ON CONFLICT (id) DO UPDATE SET title = $2, level = $3, description = $4, tags = $5, file = $6, source = $7,
				mode = $8, enabled = $9, group_by = $10, suppress_s = $11, instructions = $12, threshold = $13, loaded_at = $14,
				removed_at = NULL, file_enabled = $15`,
				r.ID, r.Title, r.Level, r.Description, nonNil(r.Tags), r.File, r.Source, r.Mode, r.Enabled, nonNil(r.GroupBy),
				r.SuppressS, r.Instructions, r.Threshold, now, r.FileEnabled); err != nil {
				return err
			}
		}
		if err := recordVersions(ctx, tx, rules, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE gjallarhorn.rules SET removed_at = $2 WHERE removed_at IS NULL AND NOT (id = ANY($1))`,
			ids, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gjallarhorn.rule_errors`); err != nil {
			return err
		}
		for _, e := range errs {
			if _, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.rule_errors (file, error, seen_at) VALUES ($1, $2, $3)`,
				e.File, e.Error, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Hit to trafienie reguły w zdarzeniu.
type Hit struct {
	RuleID    string
	RuleTitle string
	Level     string
	Engine    string
	// GroupFields: pola klucza (puste = każde zdarzenie to osobny alert).
	GroupFields map[string]string
	GroupKey    string
	Suppress    time.Duration
	EventID     string
	EventTime   time.Time
	AgentID     string
	HostName    string
	UserName    string
	SourceIP    string
	Summary     string
	// Instructions: instrukcja reguły z podstawionymi wartościami zdarzenia.
	Instructions string
}

// Observation to zdarzenie pasujące do reguły progowej (stan progu).
type Observation struct {
	RuleID      string
	Sig         string
	GroupKey    string
	GroupFields map[string]string
	EventID     string
	EventTime   time.Time
	Value       string // wartość pola distinct
	AgentID     string
	HostName    string
	UserName    string
	SourceIP    string
	ExpiresAt   time.Time
	InAlert     bool // zdarzenie jest już w alercie (tylko odczyt stanu)
}

// RecordResult mówi, co stało się z trafieniami.
type RecordResult struct {
	NewAlerts  int
	Merged     int // dopisane do istniejących alertów
	Duplicates int // zdarzenie już przypisane (ponowne dostarczenie)
}

// Record zapisuje trafienia i stan progów w jednej transakcji: zdarzenie
// już przypisane do reguły jest pomijane, trafienie z kluczem łączy się
// z otwartym alertem z okna Suppress, a nowy alert dostaje wpis w outboxie.
func (p *PG) Record(ctx context.Context, hits []Hit, obs []Observation) (RecordResult, error) {
	if len(hits) == 0 && len(obs) == 0 {
		return RecordResult{}, nil
	}
	return p.record(ctx, hits, obs, nil)
}

// RecordIndex zapisuje trafienia silnika zapytań i jego punkt kontrolny
// (zdarzenia przyjęte do checkpoint są ocenione) w jednej transakcji.
func (p *PG) RecordIndex(ctx context.Context, hits []Hit, checkpoint time.Time) (RecordResult, error) {
	return p.record(ctx, hits, nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.index_state (id, checkpoint, updated_at) VALUES (1, $1, now())
			ON CONFLICT (id) DO UPDATE SET checkpoint = greatest(gjallarhorn.index_state.checkpoint, $1), updated_at = now()`,
			checkpoint)
		return err
	})
}

// IndexCheckpoint zwraca punkt kontrolny silnika zapytań (ok=false – brak).
func (p *PG) IndexCheckpoint(ctx context.Context) (time.Time, bool, error) {
	var t time.Time
	err := p.pool.QueryRow(ctx, `SELECT checkpoint FROM gjallarhorn.index_state WHERE id = 1`).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	return t, err == nil, err
}

func (p *PG) record(ctx context.Context, hits []Hit, obs []Observation, extra func(pgx.Tx) error) (RecordResult, error) {
	var res RecordResult
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		res = RecordResult{}
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		if len(obs) > 0 {
			b := &pgx.Batch{}
			for _, o := range obs {
				gf, _ := json.Marshal(nonNilMap(o.GroupFields))
				b.Queue(`INSERT INTO gjallarhorn.threshold_events (rule_id, event_id, sig, group_key, group_fields, event_time,
					value, agent_id, host_name, user_name, source_ip, expires_at)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING`,
					o.RuleID, o.EventID, o.Sig, o.GroupKey, gf, o.EventTime, o.Value, o.AgentID, o.HostName, o.UserName,
					o.SourceIP, o.ExpiresAt)
			}
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}
		return recordHits(ctx, tx, hits, &res)
	})
	return res, err
}

// recordHits zapisuje trafienia operacjami zbiorczymi (etap 8: przy
// długim ataku – setki trafień na sekundę dołączanych do tego samego alertu –
// cztery polecenia na trafienie obciążały bazę bardziej niż reszta systemu):
//
//  1. rezerwacja par (reguła, zdarzenie) jednym INSERT-em – zdarzenia już
//     przypisane (ponowne dostarczenie) są pomijane;
//  2. otwarte alerty kluczy z paczki jednym zapytaniem (FOR UPDATE);
//  3. łączenie w pamięci w kolejności trafień – jak wcześniej: alert reguły
//     i klucza z okna ±Suppress o największym id, w tym utworzony przed
//     chwilą w tej samej paczce;
//  4. jedna aktualizacja na alert i jedno zbiorcze przypisanie zdarzeń.
func recordHits(ctx context.Context, tx pgx.Tx, hits []Hit, res *RecordResult) error {
	if len(hits) == 0 {
		return nil
	}
	rules := make([]string, len(hits))
	events := make([]string, len(hits))
	times := make([]time.Time, len(hits))
	for i, h := range hits {
		rules[i], events[i], times[i] = h.RuleID, h.EventID, h.EventTime
	}
	rows, err := tx.Query(ctx, `INSERT INTO gjallarhorn.alert_events (rule_id, event_id, alert_id, event_time)
		SELECT r, e, NULL, t FROM unnest($1::text[], $2::text[], $3::timestamptz[]) AS h(r, e, t)
		ON CONFLICT DO NOTHING RETURNING rule_id, event_id`, rules, events, times)
	if err != nil {
		return err
	}
	reserved := map[[2]string]bool{}
	for rows.Next() {
		var r, e string
		if err := rows.Scan(&r, &e); err != nil {
			rows.Close()
			return err
		}
		reserved[[2]string{r, e}] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var fresh []Hit
	for _, h := range hits {
		k := [2]string{h.RuleID, h.EventID}
		if !reserved[k] {
			res.Duplicates++
			continue
		}
		delete(reserved, k) // to samo zdarzenie drugi raz w paczce – duplikat
		fresh = append(fresh, h)
	}
	if len(fresh) == 0 {
		return nil
	}

	type open struct {
		id          int64
		first, last time.Time
		hits        int
		touched     bool
	}
	cands := map[[2]string][]*open{} // (reguła, klucz) → otwarte alerty
	var keyRules, keyKeys []string
	var lo, hi time.Time
	seen := map[[2]string]bool{}
	for _, h := range fresh {
		if h.GroupFields == nil || h.Suppress <= 0 {
			continue
		}
		if a := h.EventTime.Add(-h.Suppress); lo.IsZero() || a.Before(lo) {
			lo = a
		}
		if b := h.EventTime.Add(h.Suppress); b.After(hi) {
			hi = b
		}
		if k := [2]string{h.RuleID, h.GroupKey}; !seen[k] {
			seen[k] = true
			keyRules, keyKeys = append(keyRules, h.RuleID), append(keyKeys, h.GroupKey)
		}
	}
	if len(keyRules) > 0 {
		rows, err := tx.Query(ctx, `SELECT a.id, a.rule_id, a.group_key, a.first_seen, a.last_seen FROM gjallarhorn.alerts a
			JOIN unnest($1::text[], $2::text[]) AS k(r, g) ON a.rule_id = k.r AND a.group_key = k.g
			WHERE a.status <> 'closed' AND a.last_seen >= $3 AND a.first_seen <= $4
			ORDER BY a.id FOR UPDATE OF a`, keyRules, keyKeys, lo, hi)
		if err != nil {
			return err
		}
		for rows.Next() {
			var o open
			var r, g string
			if err := rows.Scan(&o.id, &r, &g, &o.first, &o.last); err != nil {
				rows.Close()
				return err
			}
			k := [2]string{r, g}
			cands[k] = append(cands[k], &o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}

	ids := make([]int64, len(fresh))
	for i, h := range fresh {
		var target *open
		k := [2]string{h.RuleID, h.GroupKey}
		if h.GroupFields != nil && h.Suppress > 0 {
			for _, o := range cands[k] { // rosnąco po id – wygrywa największe
				if !o.last.Before(h.EventTime.Add(-h.Suppress)) && !o.first.After(h.EventTime.Add(h.Suppress)) {
					target = o
				}
			}
		}
		if target != nil {
			target.hits++
			target.touched = true
			if h.EventTime.After(target.last) {
				target.last = h.EventTime
			}
			if h.EventTime.Before(target.first) {
				target.first = h.EventTime
			}
			ids[i] = target.id
			res.Merged++
			continue
		}
		gf, _ := json.Marshal(nonNilMap(h.GroupFields))
		var id int64
		if err := tx.QueryRow(ctx, `INSERT INTO gjallarhorn.alerts (rule_id, rule_title, level, engine, group_key, group_fields,
			first_seen, last_seen, agent_id, host_name, user_name, source_ip, first_event_id, summary, instructions)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
			h.RuleID, h.RuleTitle, h.Level, h.Engine, h.GroupKey, gf, h.EventTime, h.AgentID, h.HostName, h.UserName,
			h.SourceIP, h.EventID, h.Summary, h.Instructions).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gjallarhorn.outbox (alert_id) VALUES ($1)`, id); err != nil {
			return err
		}
		res.NewAlerts++
		ids[i] = id
		if h.GroupFields != nil && h.Suppress > 0 {
			cands[k] = append(cands[k], &open{id: id, first: h.EventTime, last: h.EventTime})
		}
	}
	b := &pgx.Batch{}
	for _, list := range cands {
		for _, o := range list {
			if o.touched {
				b.Queue(`UPDATE gjallarhorn.alerts SET hits = hits + $2, last_seen = greatest(last_seen, $3),
					first_seen = least(first_seen, $4), updated_at = now() WHERE id = $1`, o.id, o.hits, o.last, o.first)
			}
		}
	}
	fr := make([]string, len(fresh))
	fe := make([]string, len(fresh))
	for i, h := range fresh {
		fr[i], fe[i] = h.RuleID, h.EventID
	}
	b.Queue(`UPDATE gjallarhorn.alert_events a SET alert_id = h.id
		FROM unnest($1::text[], $2::text[], $3::bigint[]) AS h(r, e, id) WHERE a.rule_id = h.r AND a.event_id = h.e`, fr, fe, ids)
	return tx.SendBatch(ctx, b).Close()
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// Observations zwraca zapisany stan progów (bez przeterminowanych).
func (p *PG) Observations(ctx context.Context, now time.Time) ([]Observation, error) {
	rows, err := p.pool.Query(ctx, `SELECT t.rule_id, t.sig, t.group_key, t.group_fields, t.event_id, t.event_time, t.value,
		t.agent_id, t.host_name, t.user_name, t.source_ip, t.expires_at,
		EXISTS (SELECT 1 FROM gjallarhorn.alert_events a WHERE a.rule_id = t.rule_id AND a.event_id = t.event_id
			AND a.alert_id IS NOT NULL)
		FROM gjallarhorn.threshold_events t WHERE t.expires_at > $1 ORDER BY t.event_time`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Observation, error) {
		var o Observation
		err := r.Scan(&o.RuleID, &o.Sig, &o.GroupKey, &o.GroupFields, &o.EventID, &o.EventTime, &o.Value, &o.AgentID,
			&o.HostName, &o.UserName, &o.SourceIP, &o.ExpiresAt, &o.InAlert)
		return o, err
	})
}

// PruneObservations usuwa przeterminowany stan progów.
func (p *PG) PruneObservations(ctx context.Context, now time.Time) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.threshold_events WHERE expires_at <= $1`, now)
	return tag.RowsAffected(), err
}

// FilterNew zwraca trafienia, których para (reguła, zdarzenie) nie jest
// jeszcze w alertach (jedno zapytanie zamiast próby zapisu każdego).
func (p *PG) FilterNew(ctx context.Context, hits []Hit) ([]Hit, error) {
	rules := make([]string, len(hits))
	events := make([]string, len(hits))
	for i, h := range hits {
		rules[i], events[i] = h.RuleID, h.EventID
	}
	rows, err := p.pool.Query(ctx, `SELECT a.rule_id, a.event_id FROM gjallarhorn.alert_events a
		JOIN unnest($1::text[], $2::text[]) AS h(rule_id, event_id) USING (rule_id, event_id)
		WHERE a.alert_id IS NOT NULL`, rules, events)
	if err != nil {
		return nil, err
	}
	known := map[[2]string]bool{}
	for rows.Next() {
		var r, e string
		if err := rows.Scan(&r, &e); err != nil {
			rows.Close()
			return nil, err
		}
		known[[2]string{r, e}] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if !known[[2]string{h.RuleID, h.EventID}] {
			out = append(out, h)
		}
	}
	return out, nil
}

// KnownEvents zwraca te z podanych zdarzeń, które są już w alertach reguły.
func (p *PG) KnownEvents(ctx context.Context, rule string, ids []string) (map[string]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT event_id FROM gjallarhorn.alert_events
		WHERE rule_id = $1 AND event_id = ANY($2) AND alert_id IS NOT NULL`, rule, ids)
	if err != nil {
		return nil, err
	}
	found, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := make(map[string]bool, len(found))
	for _, id := range found {
		out[id] = true
	}
	return out, err
}
