package detector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/ext"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/internal/model"
)

// Silnik zapytań (tryb index_query): reguły skompilowane do SQL wykonywane
// cyklicznie na tabeli siem.events w ClickHouse.
//
// Każdy przebieg ocenia zdarzenia PRZYJĘTE (kolumna ingested) od kursora do
// „do” – więc także zdarzenia spóźnione, z dawnym czasem wystąpienia (bufor
// agenta, odtworzenie). Jedno zapytanie obejmuje wszystkie reguły (jeden
// odczyt tabeli). Dla reguł progowych drugie zapytanie dociąga kontekst:
// zdarzenia tych samych kluczy z ±(Window + Suppress) wokół nowych, a okna
// liczy ten sam kod Go co silnik w locie (thresholdMarks).
//
// Para (reguła, zdarzenie) trafia do alertu najwyżej raz, więc nakładające
// się przebiegi i równoległa praca silnika w locie nie dublują alertów.

// MaxIndexRows: najwięcej zdarzeń w jednym przebiegu; przy większej liczbie
// przebieg kończy się na ostatnim pobranym wierszu (Next), a następny
// zaczyna dokładnie za nim.
const MaxIndexRows = 50000

// Index to silnik zapytań.
type Index struct {
	Conn  driver.Conn
	Table string // domyślnie siem.events
	// MaxRows: limit wierszy przebiegu (domyślnie MaxIndexRows).
	MaxRows int
	// Known zwraca zdarzenia reguły, które już są w alertach (zaczepienie
	// łańcucha progów, gdy okno wypadło z zakresu zapytania). Może być nil.
	Known func(ctx context.Context, rule string, ids []string) (map[string]bool, error)
}

// Cursor wskazuje pozycję w zdarzeniach po czasie przyjęcia: przebieg
// czyta wiersze (ingested, event_id) większe niż kursor. Pusty EventID =
// od chwili Ingested włącznie.
type Cursor struct {
	Ingested time.Time
	EventID  string
}

// RuleFailure to reguła, której SQL nie wykonał się w ClickHouse
// (pominięta w przebiegu, żeby nie blokować pozostałych).
type RuleFailure struct {
	RuleID string
	Err    string
}

// IndexResult opisuje przebieg.
type IndexResult struct {
	Hits    []alerts.Hit
	Rows    int       // zdarzenia pasujące do którejś reguły
	Context int       // zdarzenia kontekstu progów
	Reached time.Time // zdarzenia przyjęte przed tą chwilą są ocenione
	// More: limit wierszy – reszta od Next w następnym przebiegu.
	More   bool
	Next   Cursor
	Failed []RuleFailure
}

// eventCols: kolumny zdarzenia w kolejności scanEvent – bez surowego XML
// (reguły dopasowuje SQL, a raw to większość danych zdarzenia: przy
// nadrabianiu zaległości 50 000 wierszy zajmowało ok. 200 MB, etap 8).
// Alias nie może się nazywać raw – w ClickHouse przesłoniłby kolumnę w WHERE.
var eventCols = strings.Replace(detect.EventColumns, "fields, raw,", "fields, '' AS raw_skipped,", 1)

func init() {
	if eventCols == detect.EventColumns {
		panic("detector: zmieniona lista kolumn detect.EventColumns – popraw eventCols")
	}
}

func scanEvent(rows driver.Rows, extra ...any) (model.Event, error) {
	var e model.Event
	err := rows.Scan(append(detect.EventDest(&e), extra...)...)
	e.Timestamp, e.Ingested = e.Timestamp.UTC(), e.Ingested.UTC()
	return e, err
}

func (x *Index) maxRows() int {
	if x.MaxRows > 0 {
		return x.MaxRows
	}
	return MaxIndexRows
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

func ms(t time.Time) string { return fmt.Sprintf("fromUnixTimestamp64Milli(%d, 'UTC')", t.UnixMilli()) }

// rangeSQL: wiersze za kursorem i przyjęte najpóźniej w to.
func (x *Index) rangeSQL(from Cursor, to time.Time) string {
	return fmt.Sprintf("(ingested, event_id) > (%s, %s) AND ingested >= %s AND ingested <= %s",
		ms(from.Ingested), detect.Quote(from.EventID), ms(from.Ingested), ms(to))
}

// Run ocenia zdarzenia przyjęte od from (kursor) do to.
func (x *Index) Run(ctx context.Context, rules []*detect.Rule, from Cursor, to time.Time) (IndexResult, error) {
	res := IndexResult{Reached: to}
	if len(rules) == 0 || to.Before(from.Ingested) {
		return res, nil
	}
	err := x.scan(ctx, rules, from, to, &res)
	if err == nil || ctx.Err() != nil {
		return res, err
	}
	// Zapytanie łączne nie przeszło – szukamy reguł, których SQL się nie
	// wykonuje (np. wyrażenie regularne odrzucone przez ClickHouse), i oceniamy
	// pozostałe. Gdy nie przechodzi żadna (albo każda osobno przechodzi), to
	// nie wina reguł (np. ClickHouse niedostępny) – przebieg kończy się
	// błędem i punkt kontrolny stoi.
	var ok []*detect.Rule
	var failed []RuleFailure
	for _, r := range rules {
		q := fmt.Sprintf("SELECT count() FROM %s WHERE %s AND (%s)", x.table(), x.rangeSQL(from, to), r.SQL())
		var n uint64
		if e := x.Conn.QueryRow(ctx, q).Scan(&n); e != nil {
			failed = append(failed, RuleFailure{RuleID: r.ID, Err: e.Error()})
			continue
		}
		ok = append(ok, r)
	}
	if len(ok) == 0 || len(failed) == 0 {
		return res, err
	}
	res = IndexResult{Reached: to}
	if err := x.scan(ctx, ok, from, to, &res); err != nil {
		return res, err
	}
	res.Failed = failed
	return res, nil
}

func (x *Index) scan(ctx context.Context, rules []*detect.Rule, from Cursor, to time.Time, res *IndexResult) error {
	conds := make([]string, len(rules))
	flags := make([]string, len(rules))
	for i, r := range rules {
		conds[i] = r.SQL()
		flags[i] = "toUInt8(" + conds[i] + ")"
	}
	q := fmt.Sprintf(`SELECT %s, [%s] FROM %s WHERE %s AND (%s) ORDER BY ingested, event_id LIMIT %d`,
		eventCols, strings.Join(flags, ", "), x.table(), x.rangeSQL(from, to), strings.Join(conds, " OR "), x.maxRows())
	rows, err := x.Conn.Query(ctx, q)
	if err != nil {
		return fmt.Errorf("zapytanie reguł: %w", err)
	}
	type cand struct {
		events []detect.Event
		keys   map[string][]string // klucz → wartości pól klucza
		lo, hi time.Time
	}
	cands := map[int]*cand{}
	seen := map[string]bool{} // reguła + zdarzenie (duplikaty w ReplacingMergeTree)
	var last Cursor
	for rows.Next() {
		var fl []uint8
		e, err := scanEvent(rows, &fl)
		if err != nil {
			rows.Close()
			return err
		}
		res.Rows++
		last = Cursor{Ingested: e.Ingested, EventID: e.ID}
		ev := detect.Event{Event: &e}
		for i, f := range fl {
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
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if res.Rows == x.maxRows() {
		// Limit – reszta od ostatniego wiersza; ocenione na pewno tylko
		// zdarzenia przyjęte przed jego chwilą.
		res.More, res.Next, res.Reached = true, last, last.Ingested
	}
	idx := make([]int, 0, len(cands))
	for i := range cands {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		hits, n, err := x.threshold(ctx, rules[i], cands[i].events, cands[i].keys, cands[i].lo, cands[i].hi)
		if err != nil {
			return fmt.Errorf("próg %s: %w", rules[i].ID, err)
		}
		res.Context += n
		res.Hits = append(res.Hits, hits...)
	}
	return nil
}

// threshold dociąga kontekst kluczy reguły progowej (jednym zapytaniem,
// klucze w tabeli zewnętrznej) i wyznacza trafienia w seriach zawierających
// nowe zdarzenia.
func (x *Index) threshold(ctx context.Context, r *detect.Rule, fresh []detect.Event, keys map[string][]string,
	lo, hi time.Time) ([]alerts.Hit, int, error) {
	span := time.Duration(r.Heimdall.Threshold.Window) + time.Duration(r.Heimdall.Suppress)
	keySQL := r.GroupKeySQL()
	byKey := map[string][]*entry{}
	evs := map[string]detect.Event{} // ostatnie zdarzenie klucza – do opisu alertu
	ids := map[string]bool{}
	n := 0
	// Klucze idą do ClickHouse jako tabela zewnętrzna „keys” (jedno zapytanie
	// niezależnie od ich liczby). Wcześniej porcje po 500 kluczy wklejane w SQL
	// (limit długości zapytania): przy kilkudziesięciu tysiącach kluczy (np.
	// nieudane logowania z wielu adresów) przebieg robił ~100 zapytań, każde
	// skanujące miliony wierszy, i nie kończył się (etap 8).
	width := max(1, len(r.Heimdall.GroupBy))
	cols := make([]func(*ext.Table) error, width)
	names := make([]string, width)
	for i := range width {
		names[i] = fmt.Sprintf("k%d", i+1)
		cols[i] = ext.Column(names[i], "String")
	}
	tbl, err := ext.NewTable("keys", cols...)
	if err != nil {
		return nil, n, err
	}
	for _, vals := range keys {
		row := make([]any, width)
		for i := range row {
			row[i] = ""
			if i < len(vals) {
				row[i] = vals[i]
			}
		}
		if err := tbl.Append(row...); err != nil {
			return nil, n, err
		}
	}
	// Kontekst bez pełnych zdarzeń: do progu wystarczą identyfikator, czas,
	// pola opisu, klucz i wartość pola Distinct (te same małe litery co
	// GroupKey/DistinctValue). Pełne zdarzenia z mapą fields – do 20 000 na
	// klucz – zajmowały detektorowi większość czasu na odśmiecanie (etap 8).
	parts := make([]string, len(r.Heimdall.GroupBy))
	for i, f := range r.Heimdall.GroupBy {
		parts[i] = "lowerUTF8(" + detect.FieldSQL(f) + ")"
	}
	keyCol := "''"
	if len(parts) > 0 {
		keyCol = "arrayStringConcat([" + strings.Join(parts, ", ") + "], '\x1f')"
	}
	valCol := "''"
	if d := r.Heimdall.Threshold.Distinct; d != "" {
		valCol = "lowerUTF8(" + detect.FieldSQL(d) + ")"
	}
	q := fmt.Sprintf(`SELECT event_id, timestamp, agent_id, host_name, user_name, %s, %s, %s
		FROM %s WHERE timestamp >= %s AND timestamp <= %s AND (%s)
		AND %s IN (SELECT tuple(%s) FROM keys)
		ORDER BY timestamp, event_id LIMIT %d BY %s`,
		detect.IPExpr, keyCol, valCol, x.table(), ms(lo.Add(-span)), ms(hi.Add(span)), r.SQL(), keySQL,
		strings.Join(names, ", "), maxEntriesPerKey, keySQL)
	rows, err := x.Conn.Query(clickhouse.Context(ctx, clickhouse.WithExternalTable(tbl)), q)
	if err != nil {
		return nil, n, err
	}
	distinct := r.Heimdall.Threshold.Distinct != ""
	for rows.Next() {
		var o alerts.Observation
		var k string
		if err := rows.Scan(&o.EventID, &o.EventTime, &o.AgentID, &o.HostName, &o.UserName, &o.SourceIP, &k, &o.Value); err != nil {
			rows.Close()
			return nil, n, err
		}
		n++
		if ids[o.EventID] {
			continue
		}
		ids[o.EventID] = true
		o.EventTime = o.EventTime.UTC()
		if distinct && (o.Value == "" || o.Value == "-") {
			o.Value = "(brak)" // jak detect.Rule.DistinctValue
		}
		byKey[k] = append(byKey[k], &entry{Observation: o})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
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
