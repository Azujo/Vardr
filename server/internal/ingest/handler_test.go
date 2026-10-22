// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"siem/internal/contract"
)

type fakePub struct {
	seen map[string]bool
	err  error
	got  [][]byte
}

func (f *fakePub) PublishRaw(_ context.Context, agentID, batchID string, _ time.Time, body []byte) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	dup := f.seen[batchID]
	f.seen[batchID] = true
	f.got = append(f.got, body)
	return dup, nil
}

func request(t *testing.T, cn string, b contract.Batch) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_ = json.NewEncoder(zw).Encode(b)
	zw.Close()
	r := httptest.NewRequest(http.MethodPost, contract.IngestPath, &buf)
	r.Header.Set("Content-Encoding", "gzip")
	if cn != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	}
	return r
}

func batch(agent string) contract.Batch {
	return contract.Batch{Schema: contract.SchemaBatchV1, BatchID: contract.NewBatchID(), AgentID: agent, SentAt: time.Now(),
		Events: []contract.Event{{ID: agent + ":System:g0:1", Source: "wineventlog:System", Raw: "<Event/>"}}}
}

func serve(h *Handler, r *http.Request) (int, contract.Response) {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var resp contract.Response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func newHandler(p Publisher) *Handler {
	return &Handler{Pub: p, Log: slog.New(slog.DiscardHandler), PublishTimeout: time.Second}
}

func TestAcceptsValidBatchAndForwardsCompressedBody(t *testing.T) {
	p := &fakePub{}
	h := newHandler(p)
	b := batch("agt-1")
	code, resp := serve(h, request(t, "agt-1", b))
	if code != 200 || resp.Status != contract.StatusAccepted || resp.BatchID != b.BatchID {
		t.Fatalf("%d %+v", code, resp)
	}
	if len(p.got) != 1 || p.got[0][0] != 0x1f || p.got[0][1] != 0x8b {
		t.Fatal("do kolejki powinna trafić skompresowana (gzip) treść paczki")
	}
	// Ponowienie tej samej paczki: nadal 200, liczone jako duplikat.
	code, _ = serve(h, request(t, "agt-1", b))
	if code != 200 || h.Duplicates.Load() != 1 || h.Events.Load() != 1 {
		t.Fatalf("duplikat: %d dup=%d events=%d", code, h.Duplicates.Load(), h.Events.Load())
	}
}

func TestRejectsIdentityProblems(t *testing.T) {
	h := newHandler(&fakePub{})
	if code, _ := serve(h, request(t, "", batch("agt-1"))); code != http.StatusUnauthorized {
		t.Errorf("bez certyfikatu: %d", code)
	}
	if code, _ := serve(h, request(t, "agt-2", batch("agt-1"))); code != http.StatusForbidden {
		t.Errorf("podszycie: %d", code)
	}
	if code, _ := serve(h, request(t, "agt.1>x", batch("agt.1>x"))); code != http.StatusForbidden {
		t.Errorf("niebezpieczny CN: %d", code)
	}
}

func TestQueueFailureReturns503WithRetryAfter(t *testing.T) {
	h := newHandler(&fakePub{err: errors.New("nats down")})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(t, "agt-1", batch("agt-1")))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestRejectsInvalidBatch(t *testing.T) {
	h := newHandler(&fakePub{})
	b := batch("agt-1")
	b.Events[0].Raw = ""
	if code, _ := serve(h, request(t, "agt-1", b)); code != http.StatusBadRequest {
		t.Errorf("pusta treść zdarzenia: %d", code)
	}
}

func TestAdmissionThrottlesBeforeReadingBody(t *testing.T) {
	p := &fakePub{}
	h := newHandler(p)
	h.Admission = NewAdmission(1, 0.9)

	// Jedno miejsce zajęte przez trwającą paczkę → kolejna dostaje 429.
	if h.Admission.Acquire() != Admit {
		t.Fatal("pierwsze miejsce powinno być wolne")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(t, "agt-1", batch("agt-1")))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("zajęty serwer: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	h.Admission.Release()

	// Kolejka prawie pełna → 503 z dłuższym Retry-After, nic nie trafia do kolejki.
	h.Admission.SetFill(0.95)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(t, "agt-1", batch("agt-1")))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" || len(p.got) != 0 {
		t.Fatalf("pełna kolejka: %d %q got=%d", w.Code, w.Header().Get("Retry-After"), len(p.got))
	}

	// Po opróżnieniu kolejki przyjmujemy, a miejsca są zwalniane.
	h.Admission.SetFill(0.1)
	if code, _ := serve(h, request(t, "agt-1", batch("agt-1"))); code != 200 || h.Admission.InFlight() != 0 {
		t.Fatalf("po odblokowaniu: %d in_flight=%d", code, h.Admission.InFlight())
	}
	if h.Throttled.Load() != 2 || h.Rejected.Load() != 0 {
		t.Fatalf("throttled=%d rejected=%d", h.Throttled.Load(), h.Rejected.Load())
	}
}

func TestQueueFullOnPublishBlocksFurtherBatches(t *testing.T) {
	full := errors.New("maximum bytes exceeded")
	h := newHandler(&fakePub{err: full})
	h.Admission = NewAdmission(0, 0.9)
	h.QueueFull = func(err error) bool { return errors.Is(err, full) }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(t, "agt-1", batch("agt-1")))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Retry-After"))
	}
	if h.Admission.Fill() < 0.9 {
		t.Fatal("po odmowie zapisu kolejka powinna zostać oznaczona jako pełna")
	}
}
