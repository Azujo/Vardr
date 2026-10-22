// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"context"
	"fmt"
	"strings"
	"time"

	"siem/internal/reprocess"
)

// Kwarantanna (siem.quarantine): zdarzenia, których nie udało się
// znormalizować albo zapisać – z oryginałem i powodem. Panel pokazuje je
// pogrupowane i zleca ponowne przetworzenie (etap 6d).

// QuarantineFilter wybiera wpisy kwarantanny.
type QuarantineFilter struct {
	From     time.Time `json:"from"`
	Source   string    `json:"source,omitempty"` // przedrostek źródła (np. syslog:, wineventlog:Security)
	Reason   string    `json:"reason,omitempty"` // fragment powodu (bez wielkości liter)
	Agent    string    `json:"agent,omitempty"`
	EventIDs []string  `json:"event_ids,omitempty"`
}

func (f QuarantineFilter) where() (string, []any) {
	w := []string{"ingested >= fromUnixTimestamp64Milli(?, 'UTC')"}
	args := []any{f.From.UnixMilli()}
	if f.Source != "" {
		w = append(w, "startsWith(source, ?)")
		args = append(args, f.Source)
	}
	if f.Reason != "" {
		w = append(w, "positionCaseInsensitiveUTF8(reason, ?) > 0")
		args = append(args, f.Reason)
	}
	if f.Agent != "" {
		w = append(w, "agent_id = ?")
		args = append(args, f.Agent)
	}
	if len(f.EventIDs) > 0 {
		w = append(w, "has(?, event_id)")
		args = append(args, f.EventIDs)
	}
	return strings.Join(w, " AND "), args
}

// QuarantineGroup to grupa wpisów o tym samym źródle i powodzie.
type QuarantineGroup struct {
	Source  string    `json:"source"`
	Reason  string    `json:"reason"`
	Count   uint64    `json:"count"`
	Agents  uint64    `json:"agents"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Example string    `json:"example_event_id"`
}

// QuarantineEntry to wpis kwarantanny (treść skrócona do podglądu).
type QuarantineEntry struct {
	Ingested  time.Time `json:"ingested"`
	AgentID   string    `json:"agent_id"`
	EventID   string    `json:"event_id"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	Peer      string    `json:"peer,omitempty"`
	Raw       string    `json:"raw"`
	RawBytes  uint64    `json:"raw_bytes"`
	Truncated bool      `json:"truncated,omitempty"`
}

// QuarantineOverview zwraca grupy (źródło, powód) i najnowsze wpisy.
func (s *Searcher) QuarantineOverview(ctx context.Context, f QuarantineFilter, limit int) ([]QuarantineGroup, []QuarantineEntry, uint64, error) {
	where, args := f.where()
	groups := []QuarantineGroup{}
	// Powód bez liczb i identyfikatorów (np. pozycji w JSON) – grupy różnych przyczyn, nie wpisów.
	rows, err := s.Conn.Query(ctx, fmt.Sprintf(`SELECT source, any(reason), count(), uniq(agent_id), min(ingested), max(ingested), any(event_id)
		FROM siem.quarantine WHERE %s
		GROUP BY source, replaceRegexpAll(reason, '[0-9]+', '#') ORDER BY count() DESC LIMIT 100`, where), args...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ClickHouse: %w", err)
	}
	var total uint64
	for rows.Next() {
		var g QuarantineGroup
		if err := rows.Scan(&g.Source, &g.Reason, &g.Count, &g.Agents, &g.First, &g.Last, &g.Example); err != nil {
			rows.Close()
			return nil, nil, 0, err
		}
		total += g.Count
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, 0, err
	}
	rows, err = s.Conn.Query(ctx, fmt.Sprintf(`SELECT ingested, agent_id, event_id, source, reason, peer, substring(raw, 1, 4000), length(raw), truncated
		FROM siem.quarantine WHERE %s ORDER BY ingested DESC LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	entries := []QuarantineEntry{}
	for rows.Next() {
		var e QuarantineEntry
		if err := rows.Scan(&e.Ingested, &e.AgentID, &e.EventID, &e.Source, &e.Reason, &e.Peer, &e.Raw, &e.RawBytes, &e.Truncated); err != nil {
			return nil, nil, 0, err
		}
		entries = append(entries, e)
	}
	return groups, entries, total, rows.Err()
}

// QuarantineItems zwraca pełne wpisy do ponownego przetworzenia (tylko
// źródła, które da się przetworzyć; najstarsze pierwsze). Ten sam wpis
// zapisany dwukrotnie (ponowienie paczki) – raz.
func (s *Searcher) QuarantineItems(ctx context.Context, f QuarantineFilter, limit int) ([]reprocess.Item, error) {
	where, args := f.where()
	rows, err := s.Conn.Query(ctx, fmt.Sprintf(`SELECT event_id, any(agent_id), any(source), any(peer), any(truncated), any(raw), min(ingested)
		FROM siem.quarantine WHERE %s AND (startsWith(source, 'wineventlog:') OR startsWith(source, 'syslog:') OR startsWith(source, 'entra:'))
		GROUP BY event_id ORDER BY min(ingested) LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	var out []reprocess.Item
	for rows.Next() {
		var it reprocess.Item
		if err := rows.Scan(&it.EventID, &it.AgentID, &it.Source, &it.Peer, &it.Truncated, &it.Raw, &it.Ingested); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
