// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-ingest-stub to minimalny, testowy endpoint przyjmujący paczki
// od agentów (załącznik A). Zapisuje zdarzenia do pliku NDJSON zamiast do
// kolejki NATS. Służy do testowania agenta przed powstaniem właściwego
// serwera (etap 1 roadmapy).
package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"siem/internal/contract"
)

const (
	maxCompressed   = 8 << 20
	maxDecompressed = 16 << 20
)

type server struct {
	mu   sync.Mutex
	out  *os.File
	seen map[string]struct{} // deduplikacja w pamięci – wystarczy do testów laboratoryjnych
	log  *slog.Logger

	failRate float64

	batches, events, duplicates, rejected atomic.Int64
}

type storedEvent struct {
	ReceivedAt time.Time `json:"received_at"`
	AgentID    string    `json:"agent_id"`
	BatchID    string    `json:"batch_id"`
	contract.Event
}

func main() {
	listen := flag.String("listen", ":8443", "adres nasłuchu")
	caFile := flag.String("ca", "certs/ca.crt", "CA weryfikujące certyfikaty agentów")
	certFile := flag.String("cert", "certs/server.crt", "certyfikat serwera")
	keyFile := flag.String("key", "certs/server.key", "klucz serwera")
	outFile := flag.String("out", "data/events.ndjson", "plik wyjściowy NDJSON")
	failRate := flag.Float64("fail-rate", 0, "odsetek żądań odrzucanych kodem 503 (test ponowień), np. 0.3")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*listen, *caFile, *certFile, *keyFile, *outFile, *failRate, log); err != nil {
		log.Error("błąd", "err", err)
		os.Exit(1)
	}
}

func run(listen, caFile, certFile, keyFile, outFile string, failRate float64, log *slog.Logger) error {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("niepoprawny plik CA")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	s := &server{out: f, seen: map[string]struct{}{}, log: log, failRate: failRate}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+contract.IngestPath, s.ingest)

	srv := &http.Server{
		Addr:    listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS: bez certyfikatu agenta brak połączenia
			ClientCAs:    pool,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.logStats()
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	log.Info("nasłuchuję", "addr", listen, "out", outFile, "fail_rate", failRate)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	s.logStats()
	return nil
}

func (s *server) logStats() {
	s.log.Info("statystyki", "batches", s.batches.Load(), "events", s.events.Load(),
		"duplicates", s.duplicates.Load(), "rejected", s.rejected.Load())
}

func (s *server) reply(w http.ResponseWriter, code int, resp contract.Response) {
	if code != http.StatusOK {
		s.rejected.Add(1)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	// Tożsamość wynika wyłącznie z certyfikatu klienta.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.reply(w, http.StatusUnauthorized, contract.Response{Error: "brak certyfikatu klienta"})
		return
	}
	agentID := r.TLS.PeerCertificates[0].Subject.CommonName

	if s.failRate > 0 && rand.Float64() < s.failRate {
		w.Header().Set("Retry-After", "1")
		s.reply(w, http.StatusServiceUnavailable, contract.Response{Error: "symulowane przeciążenie"})
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, maxCompressed)
	switch enc := r.Header.Get("Content-Encoding"); enc {
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			s.reply(w, http.StatusBadRequest, contract.Response{Error: "niepoprawny gzip"})
			return
		}
		defer zr.Close()
		body = zr
	case "":
	default:
		s.reply(w, http.StatusUnsupportedMediaType, contract.Response{Error: "nieobsługiwane kodowanie " + enc})
		return
	}

	data, err := io.ReadAll(io.LimitReader(body, maxDecompressed+1))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe) || len(data) > maxDecompressed:
		s.reply(w, http.StatusRequestEntityTooLarge, contract.Response{Error: "paczka za duża"})
		return
	case err != nil:
		s.reply(w, http.StatusBadRequest, contract.Response{Error: "błąd odczytu: " + err.Error()})
		return
	}

	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		s.reply(w, http.StatusBadRequest, contract.Response{Error: "niepoprawny JSON"})
		return
	}
	if b.AgentID != agentID {
		s.log.Warn("niezgodna tożsamość agenta", "cert_cn", agentID, "batch_agent_id", b.AgentID)
		s.reply(w, http.StatusForbidden, contract.Response{BatchID: b.BatchID, Error: "agent_id niezgodny z certyfikatem"})
		return
	}
	if err := b.Validate(); err != nil {
		s.reply(w, http.StatusBadRequest, contract.Response{BatchID: b.BatchID, Error: err.Error()})
		return
	}

	if err := s.store(&b); err != nil {
		s.log.Error("zapis nieudany", "err", err)
		s.reply(w, http.StatusServiceUnavailable, contract.Response{BatchID: b.BatchID, Error: "zapis nieudany"})
		return
	}
	s.reply(w, http.StatusOK, contract.Response{BatchID: b.BatchID, Status: contract.StatusAccepted})
}

// store zapisuje nowe zdarzenia i robi fsync przed potwierdzeniem –
// „accepted” oznacza trwały zapis.
func (s *server) store(b *contract.Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	enc := json.NewEncoder(s.out)
	var added []string
	for _, e := range b.Events {
		if _, dup := s.seen[e.ID]; dup {
			s.duplicates.Add(1)
			continue
		}
		if err := enc.Encode(storedEvent{ReceivedAt: now, AgentID: b.AgentID, BatchID: b.BatchID, Event: e}); err != nil {
			return err
		}
		added = append(added, e.ID)
	}
	if err := s.out.Sync(); err != nil {
		return fmt.Errorf("fsync: %w", err)
	}
	for _, id := range added {
		s.seen[id] = struct{}{}
	}
	s.batches.Add(1)
	s.events.Add(int64(len(added)))
	return nil
}
