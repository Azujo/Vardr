// Package bus konfiguruje trwałe strumienie NATS JetStream serwera SIEM.
package bus

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
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

	// Trwali konsumenci (jeden na etap; repliki etapu dzielą się wiadomościami).
	ConsumerNormalizer = "normalizer"
	ConsumerWriter     = "clickhouse-writer"

	// Nagłówki wiadomości.
	HdrAgent      = "Siem-Agent"
	HdrBatch      = "Siem-Batch"
	HdrReceivedAt = "Siem-Received-At"
	HdrEncoding   = "Content-Encoding"

	// MaxMessageBytes musi być ≤ max_payload w konfiguracji serwera NATS.
	MaxMessageBytes = 8 << 20

	// errCodeStoreFailed: JetStream odmówił zapisu (np. „maximum bytes
	// exceeded” przy Discard New).
	errCodeStoreFailed jetstream.ErrorCode = 10077
)

// Limits określa pojemność kolejek. Po zapełnieniu strumień odrzuca NOWE
// wiadomości (Discard New) – ingest odpowiada wtedy agentom 503, a dane
// czekają u agentów. Nic nie jest usuwane po cichu.
type Limits struct {
	RawMaxBytes    int64
	EventsMaxBytes int64
	// MaxAge > 0 usuwa nieprzetworzone wiadomości starsze niż MaxAge
	// (ostatnia linia obrony dysku). 0 = bez limitu wieku (zalecane).
	MaxAge time.Duration
}

// DefaultLimits pasuje do laboratorium (max_file_store 20 GB w nats.conf).
var DefaultLimits = Limits{RawMaxBytes: 8 << 30, EventsMaxBytes: 8 << 30}

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

// StreamConfigs zwraca konfigurację obu strumieni.
//
// Retencja Interest: wiadomość znika dopiero, gdy potwierdzą ją wszyscy
// konsumenci – kolejka zawiera wyłącznie zaległości, a jej zapełnienie
// oznacza zator, nie upływ czasu. Discard New + MaxBytes zamienia zator
// w odmowę przyjęcia (backpressure) zamiast cichej utraty najstarszych
// danych (ustalenie K1 w roadmapie, załącznik E).
func StreamConfigs(l Limits) []jetstream.StreamConfig {
	cfgs := []jetstream.StreamConfig{
		{Name: StreamRaw, Subjects: []string{SubjectRawAll}, MaxBytes: l.RawMaxBytes},
		{Name: StreamEvents, Subjects: []string{SubjectEventsAll}, MaxBytes: l.EventsMaxBytes},
	}
	for i := range cfgs {
		cfgs[i].Storage = jetstream.FileStorage
		cfgs[i].Retention = jetstream.InterestPolicy
		cfgs[i].Discard = jetstream.DiscardNew
		cfgs[i].MaxAge = l.MaxAge
		cfgs[i].Duplicates = 10 * time.Minute
		cfgs[i].MaxMsgSize = MaxMessageBytes
	}
	return cfgs
}

// ConsumerConfigs zwraca konfigurację trwałych konsumentów (klucz: strumień).
func ConsumerConfigs() map[string]jetstream.ConsumerConfig {
	return map[string]jetstream.ConsumerConfig{
		StreamRaw: {
			Durable:       ConsumerNormalizer,
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       time.Minute,
			MaxAckPending: 256,
		},
		StreamEvents: {
			Durable:       ConsumerWriter,
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       2 * time.Minute,
			MaxAckPending: 1024,
		},
	}
}

// EnsurePipeline tworzy lub aktualizuje strumienie i ich konsumentów.
// Wywołują ją wszystkie programy serwera: przy retencji Interest
// wiadomość opublikowana, zanim istnieje konsument, zostałaby od razu
// usunięta – dlatego ingest zakłada konsumentów, zanim cokolwiek przyjmie.
func EnsurePipeline(ctx context.Context, js jetstream.JetStream, l Limits) error {
	consumers := ConsumerConfigs()
	for _, cfg := range StreamConfigs(l) {
		if _, err := js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("strumień %s: %w", cfg.Name, err)
		}
		if _, err := js.CreateOrUpdateConsumer(ctx, cfg.Name, consumers[cfg.Name]); err != nil {
			return fmt.Errorf("konsument %s/%s: %w", cfg.Name, consumers[cfg.Name].Durable, err)
		}
	}
	return nil
}

// IsQueueFull rozpoznaje odmowę zapisu z powodu zapełnionego strumienia.
func IsQueueFull(err error) bool {
	var apiErr *jetstream.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode == errCodeStoreFailed
}

// Fill to zajętość strumienia (0–1) i liczba zaległych wiadomości.
type Fill struct {
	Bytes, MaxBytes uint64
	Msgs            uint64
	Ratio           float64
}

// StreamFill odczytuje zajętość strumienia.
func StreamFill(ctx context.Context, js jetstream.JetStream, stream string) (Fill, error) {
	s, err := js.Stream(ctx, stream)
	if err != nil {
		return Fill{}, err
	}
	info, err := s.Info(ctx)
	if err != nil {
		return Fill{}, err
	}
	f := Fill{Bytes: info.State.Bytes, Msgs: info.State.Msgs}
	if info.Config.MaxBytes > 0 {
		f.MaxBytes = uint64(info.Config.MaxBytes)
		f.Ratio = float64(f.Bytes) / float64(f.MaxBytes)
	}
	return f, nil
}

// Kompresory i dekompresory są drogie w tworzeniu (setki KB stanu), więc
// są używane ponownie.
var (
	gzipWriters = sync.Pool{New: func() any {
		zw, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
		return zw
	}}
	gzipReaders sync.Pool
)

// Gzip kompresuje treść wiadomości wewnątrz serwera. Poziom BestSpeed:
// wiadomości żyją w kolejce krótko, a CPU normalizatora jest wąskim gardłem
// (pomiar K4) – ok. 3× szybciej niż poziom domyślny kosztem nieco
// większych wiadomości.
func Gzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(len(data)/4 + 64)
	zw := gzipWriters.Get().(*gzip.Writer)
	defer gzipWriters.Put(zw)
	zw.Reset(&buf)
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
	var zr *gzip.Reader
	if v := gzipReaders.Get(); v != nil {
		zr = v.(*gzip.Reader)
		if err := zr.Reset(bytes.NewReader(data)); err != nil {
			return nil, err
		}
	} else {
		var err error
		if zr, err = gzip.NewReader(bytes.NewReader(data)); err != nil {
			return nil, err
		}
	}
	defer gzipReaders.Put(zr)
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("treść po rozpakowaniu przekracza %d B", limit)
	}
	return out, nil
}
