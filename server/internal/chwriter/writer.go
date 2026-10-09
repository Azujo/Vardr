// Package chwriter zapisuje znormalizowane zdarzenia i kwarantannę do
// ClickHouse. Zapis odbywa się dużymi paczkami (ClickHouse źle znosi wiele
// małych INSERT-ów).
package chwriter

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"siem/internal/model"
)

const insertEvents = `INSERT INTO siem.events (timestamp, ingested, event_id, agent_id, event_dataset, event_code,
	event_provider, event_action, event_outcome, host_name, user_name, user_domain, source_ip, process_name,
	process_command_line, message, fields, raw, truncated, parser_version, time_quality)`

// insertReplayEvents: zdarzenia odtworzone z archiwum (osobna tabela).
const insertReplayEvents = `INSERT INTO siem.events_replay (timestamp, ingested, event_id, agent_id, event_dataset, event_code,
	event_provider, event_action, event_outcome, host_name, user_name, user_domain, source_ip, process_name,
	process_command_line, message, fields, raw, truncated, parser_version, time_quality, replay_id)`

const insertQuarantine = `INSERT INTO siem.quarantine (ingested, agent_id, event_id, source, reason, raw, peer, truncated)`

// Writer zapisuje wiersze do ClickHouse.
type Writer struct {
	Conn driver.Conn
	// Replay: zapis do siem.events_replay (ścieżka odtwarzania z archiwum).
	Replay bool
	// Table: inna tabela zdarzeń niż siem.events (testy zgodności detekcji).
	Table string
}

// Open łączy się z ClickHouse (protokół natywny).
func Open(ctx context.Context, addr, user, password string) (*Writer, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:        []string{addr},
		Auth:        clickhouse.Auth{Database: "siem", Username: user, Password: password},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ClickHouse: %w", err)
	}
	return &Writer{Conn: conn}, nil
}

// InsertEvents zapisuje zdarzenia jednym INSERT-em. Błąd konwersji wiersza
// po stronie klienta jest błędem danych (patrz IsDataError).
func (w *Writer) InsertEvents(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	query := insertEvents
	if w.Replay {
		query = insertReplayEvents
	}
	if w.Table != "" {
		query = strings.Replace(query, "siem.events", w.Table, 1)
	}
	b, err := w.Conn.PrepareBatch(ctx, query)
	if err != nil {
		return err
	}
	for _, e := range events {
		row := []any{e.Timestamp, e.Ingested, e.ID, e.AgentID, e.Dataset, e.Code,
			e.Provider, e.Action, e.Outcome, e.HostName, e.UserName, e.UserDomain, ipv6(e.SourceIP), e.ProcessName,
			e.CommandLine, e.Message, nonNil(e.Fields), e.Raw, e.Truncated, e.Parser, e.TimeQuality}
		if w.Replay {
			row = append(row, e.ReplayID)
		}
		if err := b.Append(row...); err != nil {
			_ = b.Abort()
			return &dataError{fmt.Errorf("zdarzenie %s: %w", e.ID, err)}
		}
	}
	return b.Send()
}

// InsertQuarantine zapisuje wpisy kwarantanny jednym INSERT-em.
func (w *Writer) InsertQuarantine(ctx context.Context, quarantine []model.Quarantined) error {
	if len(quarantine) == 0 {
		return nil
	}
	b, err := w.Conn.PrepareBatch(ctx, insertQuarantine)
	if err != nil {
		return err
	}
	for _, q := range quarantine {
		if err := b.Append(q.Ingested, q.AgentID, q.EventID, q.Source, q.Reason, q.Raw, q.Peer, q.Truncated); err != nil {
			_ = b.Abort()
			return err
		}
	}
	return b.Send()
}

// ipv6 zamienia tekst na adres dla kolumny IPv6 (IPv4 jako ::ffff:a.b.c.d).
// Brak lub niepoprawny adres zapisujemy jako :: (wartość domyślna).
func ipv6(s string) net.IP {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To16()
	}
	return net.IPv6zero
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
