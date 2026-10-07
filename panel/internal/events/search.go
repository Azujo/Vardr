package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// dupSlack: zapas wierszy na duplikaty usuwane po stronie panelu.
const dupSlack = 20

// ErrNotFound: brak zdarzenia (np. usunięte przez retencję).
var ErrNotFound = errors.New("nie znaleziono zdarzenia")

// Searcher wykonuje zapytania do ClickHouse (konto tylko do odczytu).
type Searcher struct {
	Conn driver.Conn
}

// Open łączy się z ClickHouse.
func Open(ctx context.Context, addr, user, password string) (*Searcher, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:        []string{addr},
		Auth:        clickhouse.Auth{Database: "siem", Username: user, Password: password},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	return &Searcher{Conn: conn}, nil
}

// Event to zdarzenie na liście wyników.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	ID        string    `json:"event_id"`
	AgentID   string    `json:"agent_id"`
	Host      string    `json:"host"`
	Dataset   string    `json:"dataset"`
	Code      uint32    `json:"code"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	User      string    `json:"user"`
	Domain    string    `json:"domain"`
	IP        string    `json:"ip"`
	Process   string    `json:"process"`
	Message   string    `json:"message"`
}

// Detail to pełne zdarzenie.
type Detail struct {
	Event
	Ingested    time.Time         `json:"ingested"`
	Provider    string            `json:"provider"`
	CommandLine string            `json:"command_line"`
	Fields      map[string]string `json:"fields"`
	Raw         string            `json:"raw"`
	Truncated   bool              `json:"truncated"`
	Parser      string            `json:"parser_version"`
	TimeQuality string            `json:"time_quality"`
}

// Cursor wskazuje ostatni wiersz poprzedniej strony (stronicowanie
// „starsze niż”, stabilne mimo napływu nowych zdarzeń).
type Cursor struct {
	Timestamp time.Time
	ID        string
}

// ipExpr pokazuje adres IPv4 bez prefiksu ::ffff: i pusty zamiast ::.
const ipExpr = `if(source_ip = toIPv6('::'), '', replaceRegexpOne(toString(source_ip), '^::ffff:', ''))`

const listCols = `timestamp, event_id, agent_id, host_name, event_dataset, event_code, event_action, event_outcome,
	user_name, user_domain, ` + ipExpr + `, process_name, substring(message, 1, 300)`

// where buduje warunek: zakres czasu (z zawężeniem partycji po czasie
// przyjęcia) i warunki zapytania.
func where(p Parsed, from, to time.Time) (string, []any) {
	// Partycje są dzienne po „ingested”; zdarzenie nie mogło zostać przyjęte
	// przed wystąpieniem (zapas 1 h na rozjazd zegarów) – to pozwala pominąć
	// stare partycje.
	conds := []string{"timestamp >= ?", "timestamp < ?", "ingested >= ?"}
	args := []any{from, to, from.Add(-time.Hour)}
	for _, c := range p.Conds {
		conds = append(conds, c.SQL)
		args = append(args, c.Args...)
	}
	if tc, ok := p.TextCondition(); ok {
		conds = append(conds, tc.SQL)
		args = append(args, tc.Args...)
	}
	return strings.Join(conds, " AND "), args
}

// Search zwraca do limit zdarzeń od najnowszych.
func (s *Searcher) Search(ctx context.Context, p Parsed, from, to time.Time, before *Cursor, limit int) ([]Event, error) {
	w, args := where(p, from, to)
	if before != nil {
		w += " AND (timestamp, event_id) < (?, ?)"
		args = append(args, before.Timestamp, before.ID)
	}
	// Zwykłe ORDER BY … LIMIT: baza trzyma w pamięci tylko najlepsze wiersze.
	// Duplikaty (ReplacingMergeTree usuwa je dopiero przy scalaniu) usuwamy
	// niżej – „LIMIT 1 BY event_id” zapamiętywał identyfikatory WSZYSTKICH
	// zdarzeń z zakresu i przy 7 dniach przekraczał pamięć serwera.
	sql := `SELECT ` + listCols + ` FROM ` + table(p.Replay) + ` WHERE ` + w +
		` ORDER BY timestamp DESC, event_id DESC LIMIT ?`
	args = append(args, limit+dupSlack)
	rows, err := s.Conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Timestamp, &e.ID, &e.AgentID, &e.Host, &e.Dataset, &e.Code, &e.Action, &e.Outcome,
			&e.User, &e.Domain, &e.IP, &e.Process, &e.Message); err != nil {
			return nil, err
		}
		if len(out) > 0 && out[len(out)-1].ID == e.ID {
			continue // duplikat – ten sam identyfikator i czas sąsiadują po sortowaniu
		}
		if len(out) < limit {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

// Bucket to słupek histogramu.
type Bucket struct {
	T     time.Time `json:"t"`
	Count uint64    `json:"count"`
}

// Interval dobiera szerokość słupka histogramu (ok. 60 słupków).
func Interval(from, to time.Time) time.Duration {
	steps := []time.Duration{10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute, 10 * time.Minute,
		30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	span := to.Sub(from)
	for _, s := range steps {
		if span/s <= 90 {
			return s
		}
	}
	return 24 * time.Hour
}

// Histogram liczy zdarzenia w przedziałach czasu.
func (s *Searcher) Histogram(ctx context.Context, p Parsed, from, to time.Time) ([]Bucket, time.Duration, uint64, error) {
	step := Interval(from, to)
	w, args := where(p, from, to)
	// count(), nie uniqExact: duplikaty (przed scaleniem ReplacingMergeTree) są
	// rzadkie, a dokładne liczenie unikalnych jest wielokrotnie wolniejsze.
	sql := `SELECT toStartOfInterval(timestamp, toIntervalSecond(?)) AS t, count()
		FROM ` + table(p.Replay) + ` WHERE ` + w + ` GROUP BY t ORDER BY t`
	rows, err := s.Conn.Query(ctx, sql, append([]any{int64(step.Seconds())}, args...)...)
	if err != nil {
		return nil, step, 0, err
	}
	defer rows.Close()
	out := []Bucket{}
	var total uint64
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.T, &b.Count); err != nil {
			return nil, step, 0, err
		}
		total += b.Count
		out = append(out, b)
	}
	return out, step, total, rows.Err()
}

// Get zwraca pełne zdarzenie; ts (z listy) zawęża wyszukiwanie.
func (s *Searcher) Get(ctx context.Context, id string, ts time.Time, replay bool) (Detail, error) {
	sql := `SELECT ` + listCols + `, ingested, event_provider, process_command_line, fields, raw, truncated, parser_version, time_quality
		FROM ` + table(replay) + ` WHERE event_id = ? AND timestamp >= ? AND timestamp <= ? LIMIT 1`
	row := s.Conn.QueryRow(ctx, sql, id, ts.Add(-time.Second), ts.Add(time.Second))
	var d Detail
	e := &d.Event
	err := row.Scan(&e.Timestamp, &e.ID, &e.AgentID, &e.Host, &e.Dataset, &e.Code, &e.Action, &e.Outcome,
		&e.User, &e.Domain, &e.IP, &e.Process, &e.Message,
		&d.Ingested, &d.Provider, &d.CommandLine, &d.Fields, &d.Raw, &d.Truncated, &d.Parser, &d.TimeQuality)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return d, ErrNotFound
		}
		return d, err
	}
	return d, nil
}

// table wybiera tabelę: bieżące zdarzenia albo odtworzone z archiwum.
func table(replay bool) string {
	if replay {
		return "siem.events_replay"
	}
	return "siem.events"
}
