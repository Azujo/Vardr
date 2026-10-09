package events

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"siem/internal/detect"
	"siem/internal/model"
)

// Test reguły (panel → Reguły detekcji → „Przetestuj”): reguła skompilowana
// do SQL tak jak w silniku zapytań, wykonana na zdarzeniach z wybranego
// okresu, oraz alerty, które by z niej powstały (łączenie i progi liczone
// tym samym kodem co w detektorze). Konto siem_panel ma limity czasu
// i pamięci, więc test nie zagłodzi zapisu.

// maxTestRows: najwięcej zdarzeń analizowanych do wyznaczenia alertów.
const maxTestRows = 20000

// RuleTestEvent to zdarzenie pasujące do testowanej reguły.
type RuleTestEvent struct {
	Timestamp time.Time `json:"timestamp"`
	ID        string    `json:"event_id"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	Code      uint32    `json:"code"`
	Summary   string    `json:"summary"`
}

// RuleTestAlert to alert, który powstałby z reguły.
type RuleTestAlert struct {
	Key    map[string]string `json:"key,omitempty"`
	First  time.Time         `json:"first"`
	Last   time.Time         `json:"last"`
	Events int               `json:"events"`
	Host   string            `json:"host"`
}

// RuleTestResult to wynik testu reguły.
type RuleTestResult struct {
	Matched     uint64          `json:"matched"`
	Events      []RuleTestEvent `json:"events"`
	Alerts      []RuleTestAlert `json:"alerts"`
	AlertsTotal int             `json:"alerts_total"`
	Truncated   bool            `json:"truncated"` // alerty wyznaczone z pierwszych maxTestRows zdarzeń
	TookMS      int64           `json:"took_ms"`
}

type testSeries struct {
	t []time.Time
	v []string
}

func (s testSeries) Len() int             { return len(s.t) }
func (s testSeries) Time(i int) time.Time { return s.t[i] }
func (s testSeries) Value(i int) string   { return s.v[i] }
func (s testSeries) Seed(int) bool        { return false }

// TestRule wykonuje regułę na zdarzeniach z [from, to].
func (s *Searcher) TestRule(ctx context.Context, r *detect.Rule, from, to time.Time) (RuleTestResult, error) {
	t0 := time.Now()
	res := RuleTestResult{Events: []RuleTestEvent{}, Alerts: []RuleTestAlert{}}
	where := fmt.Sprintf("timestamp >= fromUnixTimestamp64Milli(%d, 'UTC') AND timestamp <= fromUnixTimestamp64Milli(%d, 'UTC') AND (%s)",
		from.UnixMilli(), to.UnixMilli(), r.SQL())
	if err := s.Conn.QueryRow(ctx, "SELECT count() FROM siem.events WHERE "+where).Scan(&res.Matched); err != nil {
		return res, fmt.Errorf("ClickHouse: %w", err)
	}
	rows, err := s.Conn.Query(ctx, fmt.Sprintf("SELECT %s FROM siem.events WHERE %s ORDER BY timestamp, event_id LIMIT %d",
		detect.EventColumns, where, maxTestRows))
	if err != nil {
		return res, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	type ev struct {
		e   model.Event
		key string
	}
	var evs []ev
	seen := map[string]bool{}
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(detect.EventDest(&e)...); err != nil {
			return res, err
		}
		if seen[e.ID] { // duplikaty w ReplacingMergeTree
			continue
		}
		seen[e.ID] = true
		e.Timestamp = e.Timestamp.UTC()
		evs = append(evs, ev{e: e, key: strings.Join(r.GroupKey(detect.Event{Event: &e}), "\x1f")})
	}
	if err := rows.Err(); err != nil {
		return res, err
	}
	res.Truncated = res.Matched > uint64(len(evs)) && len(evs) >= maxTestRows

	// Ostatnie zdarzenia (najnowsze pierwsze).
	for i := len(evs) - 1; i >= 0 && len(res.Events) < 50; i-- {
		e := evs[i].e
		sum := e.CommandLine
		if sum == "" {
			sum = e.Message
		}
		if len([]rune(sum)) > 200 {
			sum = string([]rune(sum)[:199]) + "…"
		}
		res.Events = append(res.Events, RuleTestEvent{Timestamp: e.Timestamp, ID: e.ID, Host: e.HostName,
			User: e.UserName, Code: e.Code, Summary: sum})
	}

	// Alerty: klucze, w nich łączenie po Suppress albo progi.
	byKey := map[string][]int{}
	var keys []string
	for i, x := range evs {
		if _, ok := byKey[x.key]; !ok {
			keys = append(keys, x.key)
		}
		byKey[x.key] = append(byKey[x.key], i)
	}
	suppress := time.Duration(r.Heimdall.Suppress)
	var out []RuleTestAlert
	add := func(idx []int) {
		first, last := evs[idx[0]].e, evs[idx[len(idx)-1]].e
		a := RuleTestAlert{First: first.Timestamp, Last: last.Timestamp, Events: len(idx), Host: first.HostName}
		if len(r.Heimdall.GroupBy) > 0 {
			a.Key = map[string]string{}
			for _, f := range r.Heimdall.GroupBy {
				v, _ := detect.Event{Event: &evs[idx[0]].e}.Get(f)
				a.Key[f] = v
			}
		}
		out = append(out, a)
	}
	for _, k := range keys {
		idx := byKey[k]
		switch {
		case r.IsThreshold():
			ser := testSeries{}
			for _, i := range idx {
				ser.t = append(ser.t, evs[i].e.Timestamp)
				ser.v = append(ser.v, r.DistinctValue(detect.Event{Event: &evs[i].e}))
			}
			marks, _, found := detect.ThresholdMarks(ser, r.Heimdall.Threshold, suppress)
			if !found {
				continue
			}
			for _, c := range detect.Components(ser, marks, suppress) {
				add(idx[c.From:c.To])
			}
		case len(r.Heimdall.GroupBy) > 0 && suppress > 0:
			start := 0
			for j := 1; j <= len(idx); j++ {
				if j == len(idx) || evs[idx[j]].e.Timestamp.Sub(evs[idx[j-1]].e.Timestamp) > suppress {
					add(idx[start:j])
					start = j
				}
			}
		default:
			for _, i := range idx {
				add([]int{i})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	res.AlertsTotal = len(out)
	if len(out) > 100 {
		out = out[:100]
	}
	res.Alerts = out
	res.TookMS = time.Since(t0).Milliseconds()
	return res, nil
}
