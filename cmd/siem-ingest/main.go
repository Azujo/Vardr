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

	"siem/internal/contract"
	"siem/internal/server/bus"
	"siem/internal/server/ingest"
	"siem/internal/server/svc"
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

	retention, err := svc.EnvDuration("SIEM_QUEUE_RETENTION", 48*time.Hour)
	if err != nil {
		return err
	}
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-ingest")
	if err != nil {
		return err
	}
	defer nc.Close()
	if err := svc.Retry(ctx, log, "konfiguracja strumieni NATS", func() error {
		return bus.EnsureStreams(ctx, js, retention)
	}); err != nil {
		return err
	}

	tlsCfg, err := serverTLS(svc.Env("SIEM_TLS_CA", "/certs/ca.crt"),
		svc.Env("SIEM_TLS_CERT", "/certs/server.crt"), svc.Env("SIEM_TLS_KEY", "/certs/server.key"))
	if err != nil {
		return err
	}

	h := &ingest.Handler{Pub: &ingest.JetStreamPublisher{JS: js}, Log: log, PublishTimeout: 10 * time.Second}
	mux := http.NewServeMux()
	mux.Handle("POST "+contract.IngestPath, h)
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
					"duplicates", h.Duplicates.Load(), "rejected", h.Rejected.Load())
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

	log.Info("nasłuchuję", "addr", srv.Addr, "queue_retention", retention)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func serverTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("niepoprawny plik CA")
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
	}, nil
}
