package detector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"siem/internal/alerts"
	"siem/server/internal/detect"
	"siem/server/internal/model"
)

// Silnik zapytań (tryb index_query): reguły skompilowane do SQL wykonywane
// cyklicznie na tabeli siem.events w ClickHouse.
//
// Każdy przebieg ocenia zdarzenia PRZYJĘTE (kolumna ingested) w przedziale
// [od, do] – więc także zdarzenia spóźnione, z dawnym czasem wystąpienia
// (bufor agenta, odtworzenie). Jedno zapytanie obejmuje wszystkie reguły
// (jeden odczyt tabeli). Dla reguł progowych drugie zapytanie dociąga
// kontekst: zdarzenia tych samych kluczy z ±(Window + Suppress) wokół
// nowych, a okna liczy ten sam kod Go co silnik w locie (thresholdMarks).
//
// Para (reguła, zdarzenie) trafia do alertu najwyżej raz, więc nakładające
// się przebiegi i równoległa praca silnika w locie nie dublują alertów.

// MaxIndexRows: najwięcej zdarzeń w jednym przebiegu; przy większej liczbie
// przebieg kończy się na ostatnim pobranym czasie przyjęcia (reszta
// w następnym).
const MaxIndexRows = 50000

// Index to silnik zapytań.
type Index struct {
	Conn  driver.Conn
	Table string // domyślnie siem.events
	// Known zwraca zdarzenia reguły, które już są w alertach (zaczepienie
	// łańcucha progów, gdy okno wypadło z zakresu zapytania). Może być nil.
	Known func(ctx context.Context, rule string, ids []string) (map[string]bool, error)
}

// IndexResult opisuje przebieg.
type IndexResult struct {
	Hits    []alerts.Hit
	Rows    int       // zdarzenia pasujące do którejś reguły
	Context int       // zdarzenia kontekstu progów
	Reached time.Time // do kiedy (ingested) zdarzenia są ocenione
}

// eventCols: kolumny zdarzenia w kolejności scanEvent.
var eventCols = `timestamp, ingested, event_id, agent_id, event_dataset, event_code, event_provider, event_action,
	event_outcome, host_name, user_name, user_domain, ` + detect.IPExpr + `, process_name, process_command_line,
	message, fields, raw`

func scanEvent(rows driver.Rows, extra ...any) (model.Event, error) {
	var e model.Event
	dest := []any{&e.Timestamp, &e.Ingested, &e.ID, &e.AgentID, &e.Dataset, &e.Code, &e.Provider, &e.Action,
		&e.Outcome, &e.HostName, &e.UserName, &e.UserDomain, &e.SourceIP, &e.ProcessName, &e.CommandLine,
		&e.Message, &e.Fields, &e.Raw}
	err := rows.Scan(append(dest, extra...)...)
	e.Timestamp, e.Ingested = e.Timestamp.UTC(), e.Ingested.UTC()
	return e, err
}

func (x *Index) table() string {
	if x.Table == "" {
		return "siem.events"
	}
	return x.Table
}

// IndexRules wybiera reguły silnika zapytań (włączone, tryb index_query albo both).
func IndexRules(all []*detect.Rule) []*detect.Rule {
	var out []*detect.Rule
	for _, r := range all {
		if r.Enabled() && (r.Heimdall.Mode == "index_query" || r.Heimdall.Mode == "both") {
			out = append(out, r)
		}
	}
	return out
}

// Run ocenia zdarzenia przyjęte w [from, to].
func (x *Index) Run(ctx context.Context, rules []*detect.Rule, from, to time.Time) (IndexResult, error) {
	res := IndexResult{Reached: to}
	if len(rules) == 0 || !to.After(from) {
		return res, nil
	}
	conds := make([]string, len(rules))
	for i, r := range rules {
		conds[i] = r.SQL()
	}
	flags := make([]string, len(conds))
	for i, c := range conds {
		flags[i] = "toUInt8(" + c + ")"
	}
	q := fmt.Sprintf(`SELECT %s, [%s] FROM %s
		WHERE ingested >= fromUnixTimestamp64Milli(%d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%d, 'UTC')
		AND (%s) ORDER BY ingested, event_id LIMIT %d`,
		eventCols, strings.Join(flags, ", "), x.table(), from.UnixMilli(), to.UnixMilli(),
		strings.Join(conds, " OR "), MaxIndexRows)
	rows, err := x.Conn.Query(ctx, q)
	if err != nil {
		return res, fmt.Errorf("zapytanie reguł: %w", err)
	}
	type cand struct {
		events []detect.Event
		keys   map[string][]string // klucz → wartości pól klucza
		lo, hi time.Time
	}
	cands := map[int]*cand{}
	seen := map[string]bool{} // reguła + zdarzenie (duplikaty w ReplacingMergeTree)
	var last time.Time
	for rows.Next() {
		var flags []uint8
		e, err := scanEvent(rows, &flags)
		if err != nil {
			rows.Close()
			return res, err
		}
		res.Rows++
		last = e.Ingested
		ev := detect.Event{Event: &e}
		for i, f := range flags {
			if f == 0 || seen[rules[i].ID+"\x00"+e.ID] {
				continue
			}
			seen[rules[i].ID+"\x00"+e.ID] = true
			r := rules[i]
			if !r.IsThreshold() {
				h := hitFor(r, ev)
				h.Engine = "index_query"
				res.Hits = append(res.Hits, h)
				continue
			}
			c := cands[i]
			if c == nil {
				c = &cand{keys: map[string][]string{}, lo: e.Timestamp, hi: e.Timestamp}
				cands[i] = c
			}
			c.events = append(c.events, ev)
			c.keys[strings.Join(r.GroupKey(ev), "\x1f")] = r.GroupKey(ev)
			if e.Timestamp.Before(c.lo) {
				c.lo = e.Timestamp
			}
			if e.Timestamp.After(c.hi) {
				c.hi = e.Timestamp
			}
		}
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	rows.Close()
	if res.Rows == MaxIndexRows {
		// Limit – ocenione na pewno tylko zdarzenia do ostatniego czasu przyjęcia.
		res.Reached = last
	}
	idx := make([]int, 0, len(cands))
	for i := range cands {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		hits, n, err := x.threshold(ctx, rules[i], cands[i].events, cands[i].keys, cands[i].lo, cands[i].hi)
		if err != nil {
			return res, fmt.Errorf("próg %s: %w", rules[i].ID, err)
		}
		res.Context += n
		res.Hits = append(res.Hits, hits...)
	}
	return res, nil
}

// threshold dociąga kontekst kluczy reguły progowej i wyznacza trafienia
// w seriach zawierających nowe zdarzenia.
func (x *Index) threshold(ctx context.Context, r *detect.Rule, fresh []detect.Event, keys map[string][]string,
	lo, hi time.Time) ([]alerts.Hit, int, error) {
	span := time.Duration(r.Heimdall.Threshold.Window) + time.Duration(r.Heimdall.Suppress)
	tuples := make([]string, 0, len(keys))
	for _, vals := range keys {
		q := make([]string, len(vals))
		for i, v := range vals {
			q[i] = detect.Quote(v)
		}
		tuples = append(tuples, "tuple("+strings.Join(q, ", ")+")")
	}
	sort.Strings(tuples)
	keySQL := r.GroupKeySQL()
	q := fmt.Sprintf(`SELECT %s FROM %s
		WHERE timestamp >= fromUnixTimestamp64Milli(%d, 'UTC') AND timestamp <= fromUnixTimestamp64Milli(%d, 'UTC')
		AND (%s) AND has([%s], %s)
		ORDER BY timestamp, event_id LIMIT %d BY %s`,
		eventCols, x.table(), lo.Add(-span).UnixMilli(), hi.Add(span).UnixMilli(), r.SQL(),
		strings.Join(tuples, ", "), keySQL, maxEntriesPerKey, keySQL)
	rows, err := x.Conn.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	byKey := map[string][]*entry{}
	evs := map[string]detect.Event{} // ostatnie zdarzenie klucza – do opisu alertu
	ids := map[string]bool{}
	n := 0
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, n, err
		}
		n++
		if ids[e.ID] {
			continue
		}
		ids[e.ID] = true
		ev := detect.Event{Event: &e}
		k := strings.Join(r.GroupKey(ev), "\x1f")
		byKey[k] = append(byKey[k], &entry{Observation: alerts.Observation{EventID: e.ID, EventTime: e.Timestamp,
			AgentID: e.AgentID, HostName: e.HostName, UserName: e.UserName, SourceIP: e.SourceIP, Value: distinctValue(r, ev)}})
		evs[k] = ev
	}
	if err := rows.Err(); err != nil {
		return nil, n, err
	}
	if x.Known != nil && len(ids) > 0 {
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		known, err := x.Known(ctx, r.ID, list)
		if err != nil {
			return nil, n, fmt.Errorf("zdarzenia w alertach: %w", err)
		}
		for _, es := range byKey {
			for _, e := range es {
				e.emitted = known[e.EventID]
			}
		}
	}
	only := map[string]bool{}
	for _, ev := range fresh {
		only[ev.ID] = true
		k := strings.Join(r.GroupKey(ev), "\x1f")
		if !ids[ev.ID] { // zdarzenie spoza kontekstu (np. limit na klucz) – dokładamy
			byKey[k] = append(byKey[k], &entry{Observation: alerts.Observation{EventID: ev.ID, EventTime: ev.Timestamp,
				AgentID: ev.AgentID, HostName: ev.HostName, UserName: ev.UserName, SourceIP: ev.SourceIP,
				Value: distinctValue(r, ev)}})
			ids[ev.ID] = true
		}
		evs[k] = ev
	}
	ks := make([]string, 0, len(byKey))
	for k := range byKey {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var hits []alerts.Hit
	for _, k := range ks {
		es := byKey[k]
		sort.Slice(es, func(i, j int) bool { return entryLess(es[i], es[j]) })
		base := hitFor(r, evs[k])
		base.Engine = "index_query"
		hits = append(hits, emit(r, evs[k], base, es, only)...)
	}
	return hits, n, nil
}
