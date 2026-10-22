// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"context"
	"fmt"
	"time"
)

// SyslogSample to wiadomość syslog z bazy – materiał do budowy dekodera
// (panel → Dekodery → „Wczytaj próbki”).
type SyslogSample struct {
	Timestamp time.Time `json:"timestamp"`
	Peer      string    `json:"peer"`
	Host      string    `json:"host"`
	Dataset   string    `json:"dataset"`
	Decoder   string    `json:"decoder,omitempty"`
	Raw       string    `json:"raw"`
}

// SyslogSamples zwraca najnowsze różne wiadomości syslog od since: tylko
// nierozpoznane (syslog.generic) albo – gdy decoder niepusty – obsłużone
// przez ten dekoder. peer ogranicza do nadawcy.
func (s *Searcher) SyslogSamples(ctx context.Context, decoder, peer string, since time.Time, limit int) ([]SyslogSample, error) {
	where := "parser_version = 'syslog-1' AND timestamp >= fromUnixTimestamp64Milli(?, 'UTC')"
	args := []any{since.UnixMilli()}
	if decoder == "" {
		where += " AND event_dataset = 'syslog.generic'"
	} else {
		where += " AND fields['decoder.id'] = ?"
		args = append(args, decoder)
	}
	if peer != "" {
		where += " AND fields['syslog.peer'] = ?"
		args = append(args, peer)
	}
	// Ta sama treść po nagłówku (np. powtarzające się „link down”) – jedna próbka.
	rows, err := s.Conn.Query(ctx, fmt.Sprintf(`SELECT max(timestamp) AS t, any(fields['syslog.peer']), any(host_name),
		any(event_dataset), any(fields['decoder.id']), argMax(raw, timestamp)
		FROM siem.events WHERE %s GROUP BY host_name, message ORDER BY t DESC LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	defer rows.Close()
	out := []SyslogSample{}
	for rows.Next() {
		var x SyslogSample
		if err := rows.Scan(&x.Timestamp, &x.Peer, &x.Host, &x.Dataset, &x.Decoder, &x.Raw); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
