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
	"siem/internal/server/metrics"
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

	limits, err := svc.QueueLimits()
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
		return bus.EnsurePipeline(ctx, js, limits)
	}); err != nil {
		return err
	}

	tlsCfg, err := serverTLS(svc.Env("SIEM_TLS_CA", "/certs/ca.crt"),
		svc.Env("SIEM_TLS_CERT", "/certs/server.crt"), svc.Env("SIEM_TLS_KEY", "/certs/server.key"))
	if err != nil {
		return err
	}

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
					"throttled", h.Throttled.Load(), "in_flight", adm.InFlight(), "queue_fill", adm.Fill())
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
