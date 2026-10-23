// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics udostępnia metryki usług serwera w formacie Prometheus
// (/metrics). Każda usługa rejestruje tylko swoje metryki; wszystkie
// metody są bezpieczne dla nil (metryki są opcjonalne, np. w testach).
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
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
	// SIEM_PPROF=1: profile Go (/debug/pprof/) na tym samym porcie – do
	// pomiarów pod obciążeniem (etap 8), np. z kontenera w sieci Dockera:
	// go tool pprof http://detector:9100/debug/pprof/profile?seconds=30
	if os.Getenv("SIEM_PPROF") == "1" {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		log.Warn("profiling enabled (SIEM_PPROF=1) – for measurements only", "addr", addr)
	}
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("metrics server failed to start", "addr", addr, "err", err)
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
		Help: "Batches being handled right now."}, inFlight)
	promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Subsystem: "ingest", Name: "queue_fill_ratio",
		Help: "SIEM_RAW queue fill level seen by admission control (0–1)."}, queueFill)
	return &Ingest{
		batches: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "ingest", Name: "batches_total",
			Help: "Batches by handling result."}, []string{"result"}),
		events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "ingest", Name: "events_total",
			Help: "Events accepted into the queue (without duplicates)."}),
		duration: promauto.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: "ingest", Name: "request_seconds",
			Help: "Batch handling time.", Buckets: prometheus.ExponentialBuckets(0.001, 2, 14)}, []string{"result"}),
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
			Help: "Batches by result (ok, poison – unreadable, retry)."}, []string{"result"}),
		Events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "normalizer", Name: "events_total",
			Help: "Normalized events."}),
		Quarantined: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "normalizer", Name: "quarantined_total",
			Help: "Events that could not be normalized."}),
		Duration: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "normalizer", Name: "batch_seconds",
			Help: "Batch normalization and publishing time.", Buckets: prometheus.ExponentialBuckets(0.0005, 2, 14)}),
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
		Rows:         c("rows_total", "Events written to siem.events."),
		Quarantined:  c("quarantined_total", "Entries written to siem.quarantine."),
		Rejected:     c("rejected_total", "Events rejected by ClickHouse (moved to quarantine)."),
		Duplicates:   c("duplicates_total", "Events skipped as already written."),
		InsertErrors: c("insert_errors_total", "Failed writes (failure – batch retried)."),
		InsertDuration: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "writer", Name: "insert_seconds",
			Help: "Time to write a batch to ClickHouse.", Buckets: prometheus.ExponentialBuckets(0.005, 2, 12)}),
		Latency: promauto.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "writer", Name: "pipeline_latency_seconds",
			Help: "Time from ingest accepting an event to writing it to the database.", Buckets: prometheus.ExponentialBuckets(0.05, 2, 14)}),
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
		fill:    g("fill_ratio", "Stream fill level relative to the limit (0–1)."),
		bytes:   g("bytes", "Bajty w strumieniu."),
		pending: g("pending_messages", "Messages waiting for a consumer."),
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
		Batches:   c("batches_total", "Batches written to the archive."),
		Bytes:     c("bytes_total", "Bytes written to archive segments."),
		Segments:  c("segments_total", "Zatwierdzone segmenty archiwum."),
		Manifests: c("manifests_total", "Utworzone manifesty godzinowe."),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "archive", Name: "errors_total",
			Help: "Archiver errors by stage."}, []string{"stage"}),
		LastSegment:   g("last_segment_timestamp_seconds", "Czas zatwierdzenia ostatniego segmentu."),
		VerifyOK:      g("verify_ok", "Result of the last integrity verification (1 = consistent, 0 = problems)."),
		VerifyProblem: g("verify_problems", "Number of problems in the last verification."),
		LastVerify:    g("last_verify_timestamp_seconds", "Completion time of the last verification."),
		Skipped: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "archive", Name: "skipped_total",
			Help: "Batches skipped by the archiver by reason (prefix, disabled, agent, group)."}, []string{"reason"}),
		DiskFree:      g("disk_free_bytes", "Wolne miejsce na dysku archiwum."),
		DiskTotal:     g("disk_total_bytes", "Rozmiar dysku archiwum."),
		Paused:        g("paused", "1 = archiving paused for lack of space (batches wait in the queue)."),
		PolicyEnabled: g("policy_enabled", "1 = the archive policy enables archiving of new batches."),
		PolicyScheduled: g("policy_scheduled_weakening",
			"1 = archive policy weakening scheduled (takes effect after the grace period, can be cancelled in the panel)."),
		PolicyRetentionDays: g("policy_retention_days", "Current archive retention (days)."),
		PolicyExcluded:      g("policy_excluded_sources", "Number of groups and agents excluded from the archive by the policy."),
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
	// Silnik zapytań (index_query).
	IndexRuns  *prometheus.CounterVec // result: ok | error
	IndexRows  prometheus.Counter
	IndexLag   prometheus.Gauge
	IndexRules prometheus.Gauge
	IndexTime  prometheus.Counter
	// IndexRuleErrors: reguły, których SQL nie przechodzi w ClickHouse.
	IndexRuleErrors prometheus.Gauge
}

func NewDetector() *Detector {
	return &Detector{
		Events: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "events_total",
			Help: "Events evaluated by rules."}),
		Matches: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "matches_total",
			Help: "Rule hits."}, []string{"rule"}),
		Alerts: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "alerts_total",
			Help: "Hit recording: new alert, appended to an alert, duplicate."}, []string{"result"}),
		Errors: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "errors_total",
			Help: "Detector errors by stage."}, []string{"stage"}),
		Rules: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "rules",
			Help: "Enabled rules evaluated in the stream."}),
		RuleErrors: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "rule_errors",
			Help: "Rule files with errors (not loaded)."}),
		EvalTime: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "eval_seconds_total",
			Help: "Total time spent evaluating events against rules."}),
		LastEvent: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "last_event_timestamp_seconds",
			Help: "Ingest time of the last evaluated event."}),
		ThresholdKeys: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "threshold_keys",
			Help: "Threshold rule keys (group_by) kept in memory."}),
		IndexRuns: promauto.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "index_runs_total",
			Help: "Query engine runs (ClickHouse)."}, []string{"result"}),
		IndexRows: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "index_rows_total",
			Help: "Events matching rules in query engine runs."}),
		IndexLag: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "index_lag_seconds",
			Help: "Query engine checkpoint lag behind the current time."}),
		IndexRules: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "index_rules",
			Help: "Enabled rules run by the query engine."}),
		IndexRuleErrors: promauto.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "detector", Name: "index_rule_errors",
			Help: "Rules skipped by the query engine (SQL rejected by ClickHouse)."}),
		IndexTime: promauto.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "detector", Name: "index_seconds_total",
			Help: "Total time of query engine runs."}),
	}
}
