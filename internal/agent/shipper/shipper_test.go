package shipper

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"siem/internal/agent/status"
	"siem/internal/contract"
)

// fakeServer odpowiada kolejnymi kodami z listy, a potem 200.
type fakeServer struct {
	mu        sync.Mutex
	responses []int
	received  []contract.Batch
	retryHdr  string
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "gzip", http.StatusBadRequest)
		return
	}
	data, _ := io.ReadAll(zr)
	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	code := http.StatusOK
	if len(f.responses) > 0 {
		code, f.responses = f.responses[0], f.responses[1:]
	}
	if code == http.StatusOK {
		f.received = append(f.received, b)
	}
	f.mu.Unlock()

	if code != http.StatusOK {
		if f.retryHdr != "" {
			w.Header().Set("Retry-After", f.retryHdr)
		}
		w.WriteHeader(code)
		return
	}
	json.NewEncoder(w).Encode(contract.Response{BatchID: b.BatchID, Status: contract.StatusAccepted})
}

func newSender(t *testing.T, srv *httptest.Server, qdir string) *HTTPSender {
	s := NewHTTPSender(srv.Client(), srv.URL+contract.IngestPath, qdir, slog.New(slog.DiscardHandler))
	s.MinBackoff, s.MaxBackoff, s.AuthBackoff = time.Millisecond, 5*time.Millisecond, 5*time.Millisecond
	return s
}

func batch(n int) *contract.Batch {
	b := &contract.Batch{Schema: contract.SchemaBatchV1, BatchID: contract.NewBatchID(), AgentID: "agt-t", SentAt: time.Now()}
	for i := 0; i < n; i++ {
		b.Events = append(b.Events, contract.Event{
			ID: contract.EventID("agt-t", "System", 0, uint64(i+1)), Source: "wineventlog:System", Raw: "<Event/>",
		})
	}
	return b
}

func TestRetriesTransientErrorsWithSameBatchID(t *testing.T) {
	f := &fakeServer{responses: []int{500, 503, 429}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	s := newSender(t, srv, "")

	b := batch(3)
	if err := s.Send(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if len(f.received) != 1 || f.received[0].BatchID != b.BatchID {
		t.Fatalf("oczekiwano jednej przyjętej paczki z tym samym batch_id: %+v", f.received)
	}
	if s.Stats.Retries.Load() != 3 || s.Stats.EventsAccepted.Load() != 3 {
		t.Fatalf("liczniki: retries=%d accepted=%d", s.Stats.Retries.Load(), s.Stats.EventsAccepted.Load())
	}
}

func TestSplitsOn413(t *testing.T) {
	f := &fakeServer{responses: []int{413}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	s := newSender(t, srv, "")

	if err := s.Send(context.Background(), batch(10)); err != nil {
		t.Fatal(err)
	}
	if len(f.received) != 2 || len(f.received[0].Events)+len(f.received[1].Events) != 10 {
		t.Fatalf("paczka powinna zostać podzielona na dwie: %d", len(f.received))
	}
	if f.received[0].Events[0].ID != contract.EventID("agt-t", "System", 0, 1) {
		t.Fatal("podział nie zachował kolejności zdarzeń")
	}
}

func TestQuarantinesOn400(t *testing.T) {
	f := &fakeServer{responses: []int{400}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	qdir := t.TempDir()
	s := newSender(t, srv, qdir)

	b := batch(2)
	if err := s.Send(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(qdir, "batch-"+b.BatchID+".json")); err != nil {
		t.Fatalf("brak pliku kwarantanny: %v", err)
	}
	if s.Stats.EventsQuarantined.Load() != 2 {
		t.Fatal("licznik kwarantanny")
	}
}

func TestHonorsRetryAfterAndCancellation(t *testing.T) {
	f := &fakeServer{responses: []int{503}, retryHdr: "3600"}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	s := newSender(t, srv, "")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, batch(1)); err == nil {
		t.Fatal("Send powinien czekać zgodnie z Retry-After i zakończyć się anulowaniem")
	}
	if len(f.received) != 0 {
		t.Fatal("paczka nie powinna zostać wysłana przed upływem Retry-After")
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		d := backoff(time.Second, time.Minute, attempt)
		if d < 500*time.Millisecond || d > time.Minute {
			t.Fatalf("attempt %d: %v poza zakresem", attempt, d)
		}
	}
}

func TestQuarantineCapAndStatus(t *testing.T) {
	f := &fakeServer{responses: []int{503, 400, 400}}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	qdir := t.TempDir()
	s := newSender(t, srv, qdir)
	tr := status.NewTracker("t", "agt-t", srv.URL, nil)
	s.AttachStatus(tr)

	// Pierwsza paczka: 503 (błąd w statusie), potem 400 → kwarantanna.
	if err := s.Send(context.Background(), batch(1)); err != nil {
		t.Fatal(err)
	}
	if st := tr.Snapshot(); st.Server.Healthy || st.Server.LastError == "" || st.Counters.Quarantined != 1 {
		t.Fatalf("status po błędach: %+v", st.Server)
	}

	// Limit kwarantanny = rozmiar istniejącego pliku → druga paczka nie trafia na dysk.
	s.QuarantineMaxBytes = dirSize(qdir)
	if err := s.Send(context.Background(), batch(1)); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(qdir); len(entries) != 1 {
		t.Fatalf("kwarantanna przekroczyła limit: %d plików", len(entries))
	}

	if err := s.Send(context.Background(), batch(1)); err != nil {
		t.Fatal(err)
	}
	if st := tr.Snapshot(); !st.Server.Healthy || st.Counters.Accepted != 1 {
		t.Fatalf("status po sukcesie: %+v / %+v", st.Server, st.Counters)
	}
}

func TestCheckServer(t *testing.T) {
	ok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ok.Close()
	if err := CheckServer(context.Background(), ok.Client(), ok.URL+contract.IngestPath); err != nil {
		t.Fatalf("405 oznacza działające połączenie: %v", err)
	}

	denied := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "agent_id niezgodny", http.StatusForbidden)
	}))
	defer denied.Close()
	if err := CheckServer(context.Background(), denied.Client(), denied.URL); err == nil {
		t.Fatal("403 powinno być błędem")
	}

	// Klient bez zaufania do CA serwera testowego.
	if err := CheckServer(context.Background(), &http.Client{}, ok.URL); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("nieznane CA: %v", err)
	}
}
