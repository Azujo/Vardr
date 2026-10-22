// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"context"
	"fmt"
	"time"

	"siem/internal/detect"
	"siem/internal/model"
)

// EventRef wskazuje zdarzenie (id i czas – zawęża odczyt do partycji).
type EventRef struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"ts"`
}

// LoadEvents pobiera pełne zdarzenia (kreator korelacji: przykłady, z których
// powstają reguły bazowe i klucz). Brakujących nie zgłasza – zwraca znalezione.
func (s *Searcher) LoadEvents(ctx context.Context, refs []EventRef) ([]model.Event, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	ids := make([]string, len(refs))
	from, to := refs[0].Timestamp, refs[0].Timestamp
	for i, r := range refs {
		ids[i] = r.ID
		if r.Timestamp.Before(from) {
			from = r.Timestamp
		}
		if r.Timestamp.After(to) {
			to = r.Timestamp
		}
	}
	rows, err := s.Conn.Query(ctx, fmt.Sprintf(`SELECT %s FROM siem.events WHERE event_id IN ?
		AND timestamp >= fromUnixTimestamp64Milli(%d, 'UTC') AND timestamp <= fromUnixTimestamp64Milli(%d, 'UTC')
		ORDER BY timestamp, event_id LIMIT 1 BY event_id`, detect.EventColumns,
		from.Add(-time.Second).UnixMilli(), to.Add(time.Second).UnixMilli()), ids)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(detect.EventDest(&e)...); err != nil {
			return nil, err
		}
		e.Timestamp = e.Timestamp.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
