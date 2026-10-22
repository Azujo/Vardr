// SPDX-License-Identifier: AGPL-3.0-or-later

// Command siem-ingest przyjmuje paczki od agentów po mTLS i zapisuje je
// w strumieniu NATS JetStream SIEM_RAW.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/contract"
	"siem/internal/fleet"
	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/ingest"
	"siem/server/internal/metrics"
	"siem/server/internal/queue"
)

func main() {
	log := svc.Logger("ingest")
	if err := run(log); err != nil {
		log.Error("zakończono z błędem", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := svc.Context()
	defer stop()

	limits, err := queue.Limits()
	if err != nil {
		return err
	}
	maxInFlight, err := svc.EnvInt("SIEM_INGEST_MAX_INFLIGHT", 64)
	if err != nil {
		return err
	}
	highWater, err := svc.EnvFloat("SIEM_INGEST_QUEUE_HIGH_WATER", 0.9)
	if err != nil {
		return err
	}
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-ingest")
	if err != nil {
		return err
	}
	defer nc.Close()
	if err := svc.Retry(ctx, log, "konfiguracja strumieni NATS", func() error {
		if err := bus.EnsurePipeline(ctx, js, limits); err != nil {
			return err
		}
		_, err := js.CreateOrUpdateStream(ctx, fleet.StreamConfig())
		return err
	}); err != nil {
		return err
	}

	// Unieważnione certyfikaty agentów (zapisuje je panel) – odrzucane przy TLS.
	revoked := fleet.NewRevokedSet()
	go func() {
		var kv jetstream.KeyValue
		if err := svc.Retry(ctx, log, "lista unieważnionych certyfikatów", func() error {
			var err error
			kv, err = fleet.EnsureRevoked(ctx, js)
			return err
		}); err != nil {
			return
		}
		for ctx.Err() == nil {
			if err := revoked.Watch(ctx, kv, log); err != nil {
				log.Warn("obserwacja unieważnień przerwana – wznawiam", "err", err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	// Certyfikaty agentów: z głównego CA (paczki laboratoryjne) i z CA agentów
	// (rejestracja tokenem, jeśli plik istnieje).
	caFiles := []string{svc.Env("SIEM_TLS_CA", "/certs/ca.crt")}
	if f := svc.Env("SIEM_TLS_AGENTS_CA", "/certs/agents-ca.crt"); fileExists(f) {
		caFiles = append(caFiles, f)
	}
	tlsCfg, err := serverTLS(caFiles, svc.Env("SIEM_TLS_CERT", "/certs/server.crt"), svc.Env("SIEM_TLS_KEY", "/certs/server.key"), revoked)
	if err != nil {
		return err
	}
	log.Info("zaufane urzędy dla certyfikatów agentów", "files", caFiles)

	adm := ingest.NewAdmission(maxInFlight, highWater)
	go adm.WatchFill(ctx, log, 2*time.Second, func(ctx context.Context) (float64, error) {
		f, err := bus.StreamFill(ctx, js, bus.StreamRaw)
		return f.Ratio, err
	})
	h := &ingest.Handler{Pub: &ingest.JetStreamPublisher{JS: js}, Log: log, PublishTimeout: 10 * time.Second,
		Admission: adm, QueueFull: bus.IsQueueFull,
		Metrics: metrics.NewIngest(func() float64 { return float64(adm.InFlight()) }, adm.Fill)}
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	mux := http.NewServeMux()
	mux.Handle("POST "+contract.IngestPath, h)
	hbMax, err := svc.EnvInt("SIEM_INGEST_MAX_HEARTBEATS", 128)
	if err != nil {
		return err
	}
	hb := &ingest.HeartbeatHandler{Pub: &ingest.JetStreamPublisher{JS: js}, Log: log, Version: svc.Version, MaxInFlight: hbMax}
	mux.Handle("POST "+contract.HeartbeatPath, hb)
	srv := &http.Server{
		Addr:              svc.Env("SIEM_LISTEN", ":8443"),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				log.Info("statystyki", "batches", h.Batches.Load(), "events", h.Events.Load(),
					"duplicates", h.Duplicates.Load(), "rejected", h.Rejected.Load(),
					"throttled", h.Throttled.Load(), "in_flight", adm.InFlight(), "queue_fill", adm.Fill(),
					"heartbeats", hb.Accepted.Load(), "heartbeats_rejected", hb.Rejected.Load())
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()

	log.Info("nasłuchuję", "addr", srv.Addr, "raw_queue_max_bytes", limits.RawMaxBytes,
		"max_in_flight", maxInFlight, "queue_high_water", highWater)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func serverTLS(caFiles []string, certFile, keyFile string, revoked *fleet.RevokedSet) (*tls.Config, error) {
	pool := x509.NewCertPool()
	for _, f := range caFiles {
		caPEM, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("niepoprawny plik CA: " + f)
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 && revoked.Has(cs.PeerCertificates[0].SerialNumber.Text(16)) {
				return errors.New("certyfikat agenta został unieważniony")
			}
			return nil
		},
	}, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
