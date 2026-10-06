// Package bus konfiguruje trwałe strumienie NATS JetStream serwera SIEM.
package bus

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// StreamRaw: surowe paczki agentów (skompresowane, jak przyszły).
	StreamRaw     = "SIEM_RAW"
	SubjectRawAll = "siem.raw.>"
	// StreamEvents: znormalizowane paczki (model.Batch, gzip+JSON).
	StreamEvents     = "SIEM_EVENTS"
	SubjectEventsAll = "siem.events.>"

	// Nagłówki wiadomości.
	HdrAgent      = "Siem-Agent"
	HdrBatch      = "Siem-Batch"
	HdrReceivedAt = "Siem-Received-At"
	HdrEncoding   = "Content-Encoding"

	// MaxMessageBytes musi być ≤ max_payload w konfiguracji serwera NATS.
	MaxMessageBytes = 8 << 20
)

// RawSubject / EventsSubject budują temat dla agenta.
func RawSubject(agentID string) string    { return "siem.raw." + agentID }
func EventsSubject(agentID string) string { return "siem.events." + agentID }

// Connect łączy się z NATS z nieskończonymi próbami ponownego połączenia.
func Connect(url, name string) (*nats.Conn, jetstream.JetStream, error) {
	nc, err := nats.Connect(url, nats.Name(name), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return nil, nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, err
	}
	return nc, js, nil
}

// EnsureStreams tworzy lub aktualizuje strumienie. Retencja zgodna
// z roadmapą: kolejka 1–2 dni (tu 48 h), okno deduplikacji 10 min.
func EnsureStreams(ctx context.Context, js jetstream.JetStream, retention time.Duration) error {
	for _, cfg := range []jetstream.StreamConfig{
		{Name: StreamRaw, Subjects: []string{SubjectRawAll}},
		{Name: StreamEvents, Subjects: []string{SubjectEventsAll}},
	} {
		cfg.Storage = jetstream.FileStorage
		cfg.Retention = jetstream.LimitsPolicy // każdy odbiorca czyta niezależnie
		cfg.MaxAge = retention
		cfg.Duplicates = 10 * time.Minute
		cfg.MaxMsgSize = MaxMessageBytes
		cfg.Discard = jetstream.DiscardOld
		if _, err := js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("strumień %s: %w", cfg.Name, err)
		}
	}
	return nil
}

// Gzip / Gunzip – pomocnicze kompresowanie treści wiadomości.
func Gzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Gunzip rozpakowuje z limitem rozmiaru (ochrona przed „bombą” kompresyjną).
func Gunzip(data []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("treść po rozpakowaniu przekracza %d B", limit)
	}
	return out, nil
}
