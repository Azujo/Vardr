// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ingest to endpoint /v1/ingest przyjmujący paczki od agentów
// (roadmapa, załącznik A). Paczka jest potwierdzana („accepted”) dopiero
// po trwałym zapisie w strumieniu NATS JetStream.
package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"siem/internal/contract"
	"siem/server/internal/metrics"
)

const (
	MaxCompressed   = 8 << 20
	MaxDecompressed = 16 << 20
)

// Publisher zapisuje surową paczkę w trwałym strumieniu. Zwraca
// duplicate=true, gdy paczka o tym batch_id była już zapisana.
type Publisher interface {
	PublishRaw(ctx context.Context, agentID, batchID string, receivedAt time.Time, gzipBody []byte) (duplicate bool, err error)
}

// agentIDPattern ogranicza identyfikatory do znaków bezpiecznych w tematach NATS.
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Handler obsługuje POST /v1/ingest.
type Handler struct {
	Pub Publisher
	Log *slog.Logger
	// PublishTimeout ogranicza czas oczekiwania na potwierdzenie z NATS.
	PublishTimeout time.Duration
	// Admission (opcjonalna) ogranicza przyjęcia przy przeciążeniu.
	Admission *Admission
	// QueueFull (opcjonalna) rozpoznaje błąd publikacji „kolejka pełna”.
	QueueFull func(error) bool
	// Metrics (opcjonalne) – metryki Prometheus.
	Metrics *metrics.Ingest

	// Rejected: paczki odrzucone (błąd agenta lub danych);
	// Throttled: paczki odesłane do ponowienia (429/503).
	Batches, Events, Duplicates, Rejected, Throttled atomic.Int64
}

// Wskazówki Retry-After (sekundy). Agent dodaje do nich losowy rozrzut,
// żeby tysiące agentów nie wróciły w tej samej sekundzie.
const (
	retryBusy      = 5
	retryQueueFull = 30
	retryNoQueue   = 5
)

func (h *Handler) reply(w http.ResponseWriter, code int, resp contract.Response) {
	if code != http.StatusOK {
		h.Rejected.Add(1)
	}
	h.write(w, code, resp)
}

// throttle odsyła paczkę do ponowienia za retryAfter sekund.
func (h *Handler) throttle(w http.ResponseWriter, code, retryAfter int, batchID, msg string) {
	h.Throttled.Add(1)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	h.write(w, code, contract.Response{BatchID: batchID, Error: msg})
}

func (h *Handler) write(w http.ResponseWriter, code int, resp contract.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	result, events := h.handle(w, r)
	h.Metrics.Observe(result, events, time.Since(start))
}

// handle obsługuje paczkę i zwraca wynik (etykieta metryk) oraz liczbę zdarzeń.
func (h *Handler) handle(w http.ResponseWriter, r *http.Request) (string, int) {
	// Tożsamość wynika wyłącznie z certyfikatu klienta (mTLS).
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		h.reply(w, http.StatusUnauthorized, contract.Response{Error: "missing client certificate"})
		return metrics.ResultRejected, 0
	}
	agentID := r.TLS.PeerCertificates[0].Subject.CommonName
	if !agentIDPattern.MatchString(agentID) {
		h.reply(w, http.StatusForbidden, contract.Response{Error: "invalid agent identifier in the certificate"})
		return metrics.ResultRejected, 0
	}

	// Kontrola przyjęcia przed odczytem treści – odmowa jest tania.
	switch h.Admission.Acquire() {
	case Busy:
		h.throttle(w, http.StatusTooManyRequests, retryBusy, "", "server busy, retry later")
		return metrics.ResultBusy, 0
	case QueueFull:
		h.throttle(w, http.StatusServiceUnavailable, retryQueueFull, "", "queue full, retry later")
		return metrics.ResultQueueFull, 0
	}
	defer h.Admission.Release()

	// Odczyt skompresowanej treści (przekazywana dalej bez ponownej kompresji).
	compressed, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxCompressed))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		h.reply(w, http.StatusRequestEntityTooLarge, contract.Response{Error: "batch too large"})
		return metrics.ResultRejected, 0
	case err != nil:
		h.reply(w, http.StatusBadRequest, contract.Response{Error: "read error"})
		return metrics.ResultRejected, 0
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "gzip" {
		h.reply(w, http.StatusUnsupportedMediaType, contract.Response{Error: "wymagane Content-Encoding: gzip"})
		return metrics.ResultRejected, 0
	}
	zr, err := gzip.NewReader(bytesReader(compressed))
	if err != nil {
		h.reply(w, http.StatusBadRequest, contract.Response{Error: "invalid gzip"})
		return metrics.ResultRejected, 0
	}
	data, err := io.ReadAll(io.LimitReader(zr, MaxDecompressed+1))
	if err != nil {
		h.reply(w, http.StatusBadRequest, contract.Response{Error: "invalid gzip"})
		return metrics.ResultRejected, 0
	}
	if len(data) > MaxDecompressed {
		h.reply(w, http.StatusRequestEntityTooLarge, contract.Response{Error: "batch too large after decompression"})
		return metrics.ResultRejected, 0
	}

	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		h.reply(w, http.StatusBadRequest, contract.Response{Error: "invalid JSON"})
		return metrics.ResultRejected, 0
	}
	if b.AgentID != agentID {
		h.Log.Warn("agent identity mismatch", "cert_cn", agentID, "batch_agent_id", b.AgentID, "remote", r.RemoteAddr)
		h.reply(w, http.StatusForbidden, contract.Response{BatchID: b.BatchID, Error: "agent_id does not match the certificate"})
		return metrics.ResultRejected, 0
	}
	if err := b.Validate(); err != nil {
		h.reply(w, http.StatusBadRequest, contract.Response{BatchID: b.BatchID, Error: err.Error()})
		return metrics.ResultRejected, 0
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.PublishTimeout)
	defer cancel()
	dup, err := h.Pub.PublishRaw(ctx, agentID, b.BatchID, time.Now().UTC(), compressed)
	if err != nil {
		// Kolejka pełna lub niedostępna – agent ponowi, dane czekają u niego.
		if h.QueueFull != nil && h.QueueFull(err) {
			h.Admission.SetFill(1) // od razu, bez czekania na kolejny pomiar
			h.throttle(w, http.StatusServiceUnavailable, retryQueueFull, b.BatchID, "queue full, retry later")
			return metrics.ResultQueueFull, 0
		}
		h.Log.Error("writing the batch to the queue failed", "agent_id", agentID, "batch_id", b.BatchID, "err", err)
		h.throttle(w, http.StatusServiceUnavailable, retryNoQueue, b.BatchID, "queue temporarily unavailable")
		return metrics.ResultQueueError, 0
	}
	h.Batches.Add(1)
	h.reply(w, http.StatusOK, contract.Response{BatchID: b.BatchID, Status: contract.StatusAccepted})
	if dup {
		h.Duplicates.Add(1)
		return metrics.ResultDuplicate, 0
	}
	h.Events.Add(int64(len(b.Events)))
	return metrics.ResultAccepted, len(b.Events)
}
