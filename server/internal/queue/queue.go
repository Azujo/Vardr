// Package queue to wspólne ustawienia kolejek NATS dla usług potoku:
// pojemność ze zmiennych środowiskowych i obserwacja zaległości.
package queue

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/metrics"
)

// Limits czyta pojemność kolejek ze zmiennych środowiskowych
// (SIEM_QUEUE_RAW_MAX_MB, SIEM_QUEUE_EVENTS_MAX_MB, SIEM_QUEUE_MAX_AGE).
// Wszystkie programy serwera muszą mieć te same wartości – każdy z nich
// aktualizuje konfigurację strumieni przy starcie.
func Limits() (bus.Limits, error) {
	l := bus.DefaultLimits
	raw, err := svc.EnvInt("SIEM_QUEUE_RAW_MAX_MB", int(l.RawMaxBytes>>20))
	if err != nil {
		return l, err
	}
	events, err := svc.EnvInt("SIEM_QUEUE_EVENTS_MAX_MB", int(l.EventsMaxBytes>>20))
	if err != nil {
		return l, err
	}
	age, err := svc.EnvDuration("SIEM_QUEUE_MAX_AGE", l.MaxAge)
	if err != nil {
		return l, err
	}
	l.RawMaxBytes, l.EventsMaxBytes, l.MaxAge = int64(raw)<<20, int64(events)<<20, age
	return l, nil
}

// Watch co 15 s mierzy zaległości odbiorcy i zajętość strumienia,
// zapisuje je w metrykach (m może być nil) i ostrzega w logu, gdy kolejka
// rośnie: powyżej warn ostrzeżenie, powyżej alarm błąd. Log pojawia się
// przy zmianie stanu oraz co 5 minut, dopóki problem trwa. Rosnąca kolejka
// to sygnał, że etap nie nadąża i trzeba dodać repliki (roadmapa, zał. E).
func Watch(ctx context.Context, log *slog.Logger, js jetstream.JetStream, stream, consumer string,
	warn, alarm float64, m *metrics.Queue) {
	const interval, remind = 15 * time.Second, 5 * time.Minute
	t := time.NewTicker(interval)
	defer t.Stop()
	level, lastLog := slog.LevelInfo, time.Time{}
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		fill, err := bus.StreamFill(qctx, js, stream)
		var pending uint64
		if err == nil {
			var c jetstream.Consumer
			if c, err = js.Consumer(qctx, stream, consumer); err == nil {
				var info *jetstream.ConsumerInfo
				if info, err = c.Info(qctx); err == nil {
					pending = info.NumPending + uint64(info.NumAckPending)
				}
			}
		}
		cancel()
		if err != nil {
			log.Warn("odczyt stanu kolejki nieudany", "stream", stream, "err", err)
			continue
		}
		m.Set(stream, consumer, fill.Ratio, fill.Bytes, pending)

		next := slog.LevelInfo
		switch {
		case fill.Ratio >= alarm:
			next = slog.LevelError
		case fill.Ratio >= warn:
			next = slog.LevelWarn
		}
		attrs := []any{"stream", stream, "fill", round(fill.Ratio), "bytes", fill.Bytes, "pending", pending}
		switch {
		case next > slog.LevelInfo && (next != level || time.Since(lastLog) >= remind):
			log.Log(ctx, next, "kolejka rośnie – etap nie nadąża (rozważ więcej replik)", attrs...)
			lastLog = time.Now()
		case next == slog.LevelInfo && level > slog.LevelInfo:
			log.Info("kolejka wróciła do normy", attrs...)
		}
		level = next
	}
}

func round(f float64) float64 { return float64(int(f*1000)) / 1000 }
