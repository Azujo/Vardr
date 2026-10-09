// Package metrics udostępnia metryki usług serwera w formacie Prometheus
// (/metrics). Każda usługa rejestruje tylko swoje metryki; wszystkie
// metody są bezpieczne dla nil (metryki są opcjonalne, np. w testach).
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const ns = "siem"

// Serve wystawia /metrics na addr (np. ":9100") do zakończenia ctx.
// Port jest dostępny tylko w sieci Dockera – nie publikujemy go na hoście.
func Serve(ctx context.Context, log *slog.Logger, addr string) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serwer metryk nie wystartował", "addr", addr, "err", err)
	}
}

// Wyniki obsługi paczki w ingest (etykieta result).
const (
	ResultAccepted   = "accepted"
	ResultDuplicate  = "duplicate"
	ResultRejected   = "rejected"
	ResultBusy       = "throttled_busy"
	ResultQueueFull  = "throttled_queue_full"
	ResultQueueError = "queue_error"
)

// Ingest: przyjmowanie paczek od agentów.
type Ingest struct {
	batches  *prometheus.CounterVec
	events   prometheus.Counter
	duration *prometheus.HistogramVec
}

// NewIngest rejestruje metryki ingest; inFlight i queueFill są odczytywane
// przy każdym pobraniu metryk.
func NewIngest(inFlight, queueFill func() float64) *Ingest {
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Subsystem: "ingest", Name: "in_flight",
		Help: "Paczki obsługiwane w tej chwili."}, inFlight)
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Subsystem: "ingest", Name: "queue_fill_ratio",
		Help: "Zajętość kolejki SIEM_RAW widziana przez kontrolę przyjęć (0–1)."}, queueFill)
	return &Ingest{
		batches: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "ingest", Name: "batches_total",
			Help: "Paczki według wyniku obsługi."}, []string{"result"}),
		events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "ingest", Name: "events_total",
			Help: "Zdarzenia przyjęte do kolejki (bez duplikatów)."}),
		duration: promauto.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: "ingest", Name: "request_seconds",
			Help: "Czas obsługi paczki.", Buckets: prometheus.ExponentialBuckets(0.001, 2, 14)}, []string{"result"}),
	}
}

// Observe zapisuje wynik obsługi jednej paczki.
func (m *Ingest) Observe(result string, events int, d time.Duration) {
	if m == nil {
		return
	}
	m.batches.WithLabelValues(result).Inc()
	m.duration.WithLabelValues(result).Observe(d.Seconds())
	if result == ResultAccepted {
		m.events.Add(float64(events))
	}
}

// Normalizer: normalizacja paczek.
type Normalizer struct {
	Batches     *prometheus.CounterVec // result: ok | poison | retry
	Events      prometheus.Counter
	Quarantined prometheus.Counter
	Duration    prometheus.Histogram
}

func NewNormalizer() *Normalizer {
	return &Normalizer{
		Batches: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "normalizer", Name: "batches_total",
			Help: "Paczki według wyniku (ok, poison – nieczytelne, retry – ponowienie)."}, []string{"result"}),
		Events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "normalizer", Name: "events_total",
			Help: "Zdarzenia znormalizowane."}),
		Quarantined: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "normalizer", Name: "quarantined_total",
			Help: "Zdarzenia, których nie udało się znormalizować."}),
		Duration: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "normalizer", Name: "batch_seconds",
			Help: "Czas normalizacji i publikacji paczki.", Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14)}),
	}
}

// Writer: zapis do ClickHouse.
type Writer struct {
	Rows, Quarantined, Rejected, Duplicates, InsertErrors prometheus.Counter
	InsertDuration                                        prometheus.Histogram
	// Latency: od przyjęcia paczki przez ingest do zapisu w bazie.
	Latency prometheus.Histogram
}

func NewWriter() *Writer {
	c := func(name, help string) prometheus.Counter {
		return promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "writer", Name: name, Help: help})
	}
	return &Writer{
		Rows:         c("rows_total", "Zdarzenia zapisane w siem.events."),
		Quarantined:  c("quarantined_total", "Wpisy zapisane w siem.quarantine."),
		Rejected:     c("rejected_total", "Zdarzenia odrzucone przez ClickHouse (przeniesione do kwarantanny)."),
		Duplicates:   c("duplicates_total", "Zdarzenia pominięte jako już zapisane."),
		InsertErrors: c("insert_errors_total", "Nieudane zapisy (awaria – paczka ponowiona)."),
		InsertDuration: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "writer", Name: "insert_seconds",
			Help: "Czas zapisu paczki do ClickHouse.", Buckets: prometheus.ExponentialBuckets(0.005, 2, 12)}),
		Latency: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "writer", Name: "pipeline_latency_seconds",
			Help: "Czas od przyjęcia zdarzenia przez ingest do zapisu w bazie.", Buckets: prometheus.ExponentialBuckets(0.05, 2, 14)}),
	}
}

// Queue: stan kolejki NATS widziany przez odbiorcę.
type Queue struct {
	fill, bytes, pending *prometheus.GaugeVec
}

func NewQueue() *Queue {
	g := func(name, help string) *prometheus.GaugeVec {
		return promauto.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: "queue", Name: name, Help: help},
			[]string{"stream", "consumer"})
	}
	return &Queue{
		fill:    g("fill_ratio", "Zajętość strumienia względem limitu (0–1)."),
		bytes:   g("bytes", "Bajty w strumieniu."),
		pending: g("pending_messages", "Wiadomości czekające na odbiorcę."),
	}
}

// Set zapisuje zmierzony stan kolejki.
func (q *Queue) Set(stream, consumer string, fill float64, bytes, pending uint64) {
	if q == nil {
		return
	}
	q.fill.WithLabelValues(stream, consumer).Set(fill)
	q.bytes.WithLabelValues(stream, consumer).Set(float64(bytes))
	q.pending.WithLabelValues(stream, consumer).Set(float64(pending))
}

// Archiver: archiwum NIS2 (Urd).
type Archiver struct {
	Batches       prometheus.Counter
	Bytes         prometheus.Counter
	Segments      prometheus.Counter
	Manifests     prometheus.Counter
	Errors        *prometheus.CounterVec
	LastSegment   prometheus.Gauge
	VerifyOK      prometheus.Gauge
	VerifyProblem prometheus.Gauge
	LastVerify    prometheus.Gauge
	Skipped       *prometheus.CounterVec
	DiskFree      prometheus.Gauge
	DiskTotal     prometheus.Gauge
	Paused        prometheus.Gauge
	// Polityka archiwum z panelu.
	PolicyEnabled       prometheus.Gauge
	PolicyScheduled     prometheus.Gauge
	PolicyRetentionDays prometheus.Gauge
	PolicyExcluded      prometheus.Gauge
}

func NewArchiver() *Archiver {
	c := func(name, help string) prometheus.Counter {
		return promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "archive", Name: name, Help: help})
	}
	g := func(name, help string) prometheus.Gauge {
		return promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "archive", Name: name, Help: help})
	}
	return &Archiver{
		Batches:   c("batches_total", "Paczki zapisane w archiwum."),
		Bytes:     c("bytes_total", "Bajty zapisane w segmentach archiwum."),
		Segments:  c("segments_total", "Zatwierdzone segmenty archiwum."),
		Manifests: c("manifests_total", "Utworzone manifesty godzinowe."),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "archive", Name: "errors_total",
			Help: "Błędy archiwizatora według etapu."}, []string{"stage"}),
		LastSegment:   g("last_segment_timestamp_seconds", "Czas zatwierdzenia ostatniego segmentu."),
		VerifyOK:      g("verify_ok", "Wynik ostatniej weryfikacji integralności (1 = zgodne, 0 = problemy)."),
		VerifyProblem: g("verify_problems", "Liczba problemów w ostatniej weryfikacji."),
		LastVerify:    g("last_verify_timestamp_seconds", "Czas zakończenia ostatniej weryfikacji."),
		Skipped: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "archive", Name: "skipped_total",
			Help: "Paczki pominięte przez archiwizator według powodu (prefix, disabled, agent, group)."}, []string{"reason"}),
		DiskFree:      g("disk_free_bytes", "Wolne miejsce na dysku archiwum."),
		DiskTotal:     g("disk_total_bytes", "Rozmiar dysku archiwum."),
		Paused:        g("paused", "1 = archiwizacja wstrzymana z braku miejsca (paczki czekają w kolejce)."),
		PolicyEnabled: g("policy_enabled", "1 = polityka archiwum włącza archiwizację nowych paczek."),
		PolicyScheduled: g("policy_scheduled_weakening",
			"1 = zaplanowane osłabienie polityki archiwum (wejdzie w życie po karencji, można je anulować w panelu)."),
		PolicyRetentionDays: g("policy_retention_days", "Obowiązująca retencja archiwum (dni)."),
		PolicyExcluded:      g("policy_excluded_sources", "Liczba grup i agentów wyłączonych z archiwum w polityce."),
	}
}

// Detector to metryki detekcji (Gjallarhorn).
type Detector struct {
	Events     prometheus.Counter
	Matches    *prometheus.CounterVec
	Alerts     *prometheus.CounterVec // result: new | merged | duplicate
	Errors     *prometheus.CounterVec
	Rules      prometheus.Gauge
	RuleErrors prometheus.Gauge
	EvalTime   prometheus.Counter
	LastEvent  prometheus.Gauge
	// ThresholdKeys: klucze reguł progowych w pamięci.
	ThresholdKeys prometheus.Gauge
}

func NewDetector() *Detector {
	return &Detector{
		Events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "events_total",
			Help: "Zdarzenia ocenione przez reguły."}),
		Matches: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "matches_total",
			Help: "Trafienia reguł."}, []string{"rule"}),
		Alerts: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "alerts_total",
			Help: "Zapis trafień: nowy alert, dopisanie do alertu, duplikat."}, []string{"result"}),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "errors_total",
			Help: "Błędy detektora według etapu."}, []string{"stage"}),
		Rules: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "rules",
			Help: "Włączone reguły wykonywane w locie."}),
		RuleErrors: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "rule_errors",
			Help: "Pliki reguł z błędami (niewczytane)."}),
		EvalTime: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "eval_seconds_total",
			Help: "Łączny czas oceny zdarzeń przez reguły."}),
		LastEvent: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "last_event_timestamp_seconds",
			Help: "Czas przyjęcia ostatniego ocenionego zdarzenia."}),
		ThresholdKeys: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "threshold_keys",
			Help: "Klucze reguł progowych (group_by) trzymane w pamięci."}),
	}
}
