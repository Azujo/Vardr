// SPDX-License-Identifier: AGPL-3.0-or-later

package chwriter

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/contract"
	"siem/internal/model"
	"siem/server/internal/loadgen"
	"siem/server/internal/normalize"
)

// benchEvents: zdarzenia z mieszanki generatora po normalizacji.
func benchEvents(tb testing.TB, n int) []model.Event {
	tb.Helper()
	now := time.Now().UTC()
	out := make([]model.Event, 0, n)
	for i := range n {
		ch, raw := loadgen.RandomEvent("LOAD-0001", uint64(i+1), now)
		e, err := normalize.Event(contract.Event{ID: fmt.Sprintf("agt-load-0001:%s:g1:%d", ch, i+1),
			Source: "wineventlog:" + ch, ReadAt: now, Raw: raw}, "agt-load-0001", now)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// testWriter: tabela o kolumnach siem.events na testowym ClickHouse, bez
// indeksów i scalania – liczy się koszt po stronie klienta.
func testWriter(tb testing.TB) *Writer {
	tb.Helper()
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		tb.Skip("SIEM_TEST_CH_ADDR not set")
	}
	user := os.Getenv("SIEM_TEST_CH_USER")
	if user == "" {
		user = "default"
	}
	ctx := context.Background()
	conn, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr},
		Auth:        clickhouse.Auth{Username: user, Password: os.Getenv("SIEM_TEST_CH_PASSWORD")},
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4}})
	if err != nil {
		tb.Fatal(err)
	}
	for _, q := range []string{`DROP TABLE IF EXISTS default.writer_bench`, `CREATE TABLE default.writer_bench (
		timestamp DateTime64(3, 'UTC'), ingested DateTime64(3, 'UTC'), event_id String, agent_id LowCardinality(String),
		event_dataset LowCardinality(String), event_code UInt32, event_provider LowCardinality(String),
		event_action LowCardinality(String), event_outcome LowCardinality(String), host_name LowCardinality(String),
		user_name String, user_domain LowCardinality(String), source_ip IPv6, process_name String,
		process_command_line String, message String, fields Map(LowCardinality(String), String), raw String,
		truncated Bool, parser_version LowCardinality(String), time_quality LowCardinality(String),
		user_identity LowCardinality(String) DEFAULT '') ENGINE = Null`} {
		if err := conn.Exec(ctx, q); err != nil {
			tb.Fatal(err)
		}
	}
	return &Writer{Conn: conn, Table: "default.writer_bench"}
}

// BenchmarkInsertEvents: cały INSERT paczki 20 000 wierszy (jak writer).
func BenchmarkInsertEvents(b *testing.B) {
	w := testWriter(b)
	events := benchEvents(b, 20000)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if err := w.InsertEvents(ctx, events); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(events))/1000, "µs/wiersz")
}

// TestInsertBlocksOnePart: bloki jednego INSERT-u sklejają się po stronie
// serwera – wciąż jedna część, nie po jednej na blok.
func TestInsertBlocksOnePart(t *testing.T) {
	w := testWriter(t)
	ctx := context.Background()
	for _, q := range []string{`DROP TABLE IF EXISTS default.writer_parts`,
		`CREATE TABLE default.writer_parts AS default.writer_bench ENGINE = MergeTree ORDER BY event_id SETTINGS old_parts_lifetime = 1`,
		`SYSTEM STOP MERGES default.writer_parts`} {
		if err := w.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	w.Table = "default.writer_parts"
	events := benchEvents(t, 3*insertBlockRows+1)
	if err := w.InsertEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	var parts, rows uint64
	if err := w.Conn.QueryRow(ctx, `SELECT count(), sum(rows) FROM system.parts WHERE database = 'default' AND table = 'writer_parts' AND active`).
		Scan(&parts, &rows); err != nil {
		t.Fatal(err)
	}
	if parts != 1 || rows != uint64(len(events)) {
		t.Fatalf("%d części, %d wierszy (oczekiwane 1, %d)", parts, rows, len(events))
	}
}
