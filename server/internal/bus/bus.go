// SPDX-License-Identifier: AGPL-3.0-or-later

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
	// ConsumerArchiver: archiwum NIS2 (Urd). Zakładany tylko przez
	// archiwizator – istnieje, gdy archiwum jest włączone.
	ConsumerArchiver = "archiver"
	// ConsumerDetector: detekcja w locie (Gjallarhorn). Zakładany przez
	// detektor; usuwa go siem-detector disable.
	ConsumerDetector = "detector"

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

// DefaultLimits pasuje do laboratorium (max_file_store 21 GB w nats.conf:
// kolejki i ich kopie dla odtwarzania 20 GB + zapas na małe magazyny).
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
		// Writer zbiera wiadomości do jednego INSERT-u (do SIEM_WRITER_MAX_ROWS
		// wierszy), więc limit niepotwierdzonych wiadomości musi pomieścić
		// pełną paczkę także z małych wiadomości: 3500 agentów po kilka
		// zdarzeń na paczkę przy limicie 1024 dawało ok. 3600 wierszy na
		// INSERT i sufit ok. 2000 zdarzeń/s (etap 8). Pamięć ogranicza liczba
		// wierszy, nie wiadomości.
		StreamEvents: {
			Durable:       ConsumerWriter,
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       2 * time.Minute,
			MaxAckPending: 16384,
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

// ArchiverConsumerConfig: potwierdzenie dopiero po zapisie segmentu na dysk,
// więc AckWait musi przekraczać maksymalny wiek segmentu z zapasem.
func ArchiverConsumerConfig(segmentAge time.Duration) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable:       ConsumerArchiver,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       max(2*time.Minute, 3*segmentAge),
		MaxAckPending: 20000,
	}
}

// EnsureArchiver zakłada konsumenta archiwum. Przy retencji Interest od tej
// chwili każda surowa paczka czeka w SIEM_RAW także na archiwizator:
// jego awaria kończy się zatorem i odmową przyjęcia (503), nie utratą
// danych w archiwum.
func EnsureArchiver(ctx context.Context, js jetstream.JetStream, segmentAge time.Duration) (jetstream.Consumer, error) {
	return js.CreateOrUpdateConsumer(ctx, StreamRaw, ArchiverConsumerConfig(segmentAge))
}

// DisableArchiver usuwa konsumenta archiwum (wyłączenie archiwizacji
// nowych paczek – bez tego zatrzymany archiwizator blokowałby kolejkę).
func DisableArchiver(ctx context.Context, js jetstream.JetStream) error {
	err := js.DeleteConsumer(ctx, StreamRaw, ConsumerArchiver)
	if errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil
	}
	return err
}

// EnsureDetector zakłada konsumenta detekcji na SIEM_EVENTS. Przy pierwszym
// utworzeniu czyta tylko nowe zdarzenia (bez lawiny alertów z zaległości).
// Jak archiwizator: zatrzymany detektor powoduje zator, nie pominięte zdarzenia.
func EnsureDetector(ctx context.Context, js jetstream.JetStream) (jetstream.Consumer, error) {
	return js.CreateOrUpdateConsumer(ctx, StreamEvents, jetstream.ConsumerConfig{
		Durable:       ConsumerDetector,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       time.Minute,
		MaxAckPending: 2048,
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
}

// DisableDetector usuwa konsumenta detekcji (wyłączenie detekcji w locie).
func DisableDetector(ctx context.Context, js jetstream.JetStream) error {
	err := js.DeleteConsumer(ctx, StreamEvents, ConsumerDetector)
	if errors.Is(err, jetstream.ErrConsumerNotFound) {
		return nil
	}
	return err
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

// Pipeline to zestaw strumieni i odbiorców jednej ścieżki przetwarzania.
// Ścieżka „live” obsługuje bieżące zdarzenia agentów; „replay” – paczki
// odtwarzane z archiwum NIS2, przetwarzane przez osobne kopie normalizatora
// i writera do osobnej tabeli (siem.events_replay). Odtwarzanie nie dotyka
// więc kolejki agentów ani danych produkcyjnych (i przyszłej detekcji).
type Pipeline struct {
	Name         string
	RawStream    string
	RawPrefix    string // temat surowej paczki: RawPrefix + agent
	EventsStream string
	EventsPrefix string
	Normalizer   string // trwały odbiorca surowych paczek
	Writer       string // trwały odbiorca zdarzeń
	Table        string // tabela ClickHouse
}

// Ścieżki przetwarzania.
var (
	Live = Pipeline{Name: "live", RawStream: StreamRaw, RawPrefix: "siem.raw.", EventsStream: StreamEvents,
		EventsPrefix: "siem.events.", Normalizer: ConsumerNormalizer, Writer: ConsumerWriter, Table: "siem.events"}
	Replay = Pipeline{Name: "replay", RawStream: "SIEM_REPLAY_RAW", RawPrefix: "siem.replay.raw.",
		EventsStream: "SIEM_REPLAY_EVENTS", EventsPrefix: "siem.replay.events.",
		Normalizer: "normalizer-replay", Writer: "clickhouse-writer-replay", Table: "siem.events_replay"}
)

// HdrReplay: numer zlecenia odtworzenia (paczki ze ścieżki replay).
const HdrReplay = "Siem-Replay"

// PipelineByName wybiera ścieżkę (SIEM_PIPELINE: live albo replay).
func PipelineByName(name string) (Pipeline, error) {
	switch name {
	case "", Live.Name:
		return Live, nil
	case Replay.Name:
		return Replay, nil
	}
	return Pipeline{}, fmt.Errorf("nieznana ścieżka %q (live albo replay)", name)
}

func (p Pipeline) RawSubject(agentID string) string    { return p.RawPrefix + agentID }
func (p Pipeline) EventsSubject(agentID string) string { return p.EventsPrefix + agentID }

// ReplayMaxBytes: pojemność strumieni odtwarzania. Po zapełnieniu
// archiwizator czeka (Discard New), więc odtwarzanie samo się dławi.
const ReplayMaxBytes = 2 << 30

// Ensure zakłada strumienie i odbiorców ścieżki. Ścieżka live korzysta
// z EnsurePipeline (limity kolejek z konfiguracji).
func (p Pipeline) Ensure(ctx context.Context, js jetstream.JetStream, l Limits) error {
	if p.Name == Live.Name {
		return EnsurePipeline(ctx, js, l)
	}
	consumers := ConsumerConfigs()
	for _, s := range []struct{ stream, prefix, durable, liveStream string }{
		{p.RawStream, p.RawPrefix, p.Normalizer, StreamRaw},
		{p.EventsStream, p.EventsPrefix, p.Writer, StreamEvents},
	} {
		cfg := jetstream.StreamConfig{Name: s.stream, Subjects: []string{s.prefix + ">"}, MaxBytes: ReplayMaxBytes,
			Storage: jetstream.FileStorage, Retention: jetstream.InterestPolicy, Discard: jetstream.DiscardNew,
			Duplicates: 10 * time.Minute, MaxMsgSize: MaxMessageBytes}
		if _, err := js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("strumień %s: %w", s.stream, err)
		}
		cc := consumers[s.liveStream]
		cc.Durable = s.durable
		if _, err := js.CreateOrUpdateConsumer(ctx, s.stream, cc); err != nil {
			return fmt.Errorf("konsument %s/%s: %w", s.stream, s.durable, err)
		}
	}
	return nil
}
