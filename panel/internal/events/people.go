package events

import (
	"context"
	"fmt"
	"time"
)

// Person to osoba (user.identity) ze zdarzeń: z jakich źródeł i kont.
type Person struct {
	Identity string    `json:"identity"`
	Events   uint64    `json:"events"`
	Failures uint64    `json:"failures"`
	Last     time.Time `json:"last"`
	Datasets []string  `json:"datasets"`
	Accounts []string  `json:"accounts"` // konta w postaci ze zdarzeń (DOMENA\konto, UPN, login)
	Hosts    uint64    `json:"hosts"`
}

// People zwraca osoby ze zdarzeń przyjętych od from (najaktywniejsze
// pierwsze); q – fragment tożsamości albo nazwy konta.
func (s *Searcher) People(ctx context.Context, from time.Time, q string, limit int) ([]Person, error) {
	where := "ingested >= fromUnixTimestamp64Milli(?, 'UTC') AND user_identity != ''"
	args := []any{from.UnixMilli()}
	if q != "" {
		where += " AND (positionCaseInsensitiveUTF8(user_identity, ?) > 0 OR positionCaseInsensitiveUTF8(user_name, ?) > 0)"
		args = append(args, q, q)
	}
	rows, err := s.Conn.Query(ctx, fmt.Sprintf(`SELECT user_identity, count(), countIf(event_outcome = 'failure'), max(timestamp),
		arraySort(groupUniqArray(20)(toString(event_dataset))),
		arraySort(groupUniqArray(20)(if(user_domain != '' AND user_domain != '-' AND position(user_name, '\\') = 0 AND position(user_name, '@') = 0,
			concat(user_domain, '\\', user_name), user_name))),
		uniq(host_name)
		FROM siem.events WHERE %s GROUP BY user_identity ORDER BY count() DESC LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	out := []Person{}
	for rows.Next() {
		var p Person
		if err := rows.Scan(&p.Identity, &p.Events, &p.Failures, &p.Last, &p.Datasets, &p.Accounts, &p.Hosts); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
