package svc

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/server/bus"
)

// QueueLimits czyta pojemność kolejek ze zmiennych środowiskowych
// (SIEM_QUEUE_RAW_MAX_MB, SIEM_QUEUE_EVENTS_MAX_MB, SIEM_QUEUE_MAX_AGE).
// Wszystkie programy serwera muszą mieć te same wartości – każdy z nich
// aktualizuje konfigurację strumieni przy starcie.
func QueueLimits() (bus.Limits, error) {
	l := bus.DefaultLimits
	raw, err := EnvInt("SIEM_QUEUE_RAW_MAX_MB", int(l.RawMaxBytes>>20))
	if err != nil {
		return l, err
	}
	events, err := EnvInt("SIEM_QUEUE_EVENTS_MAX_MB", int(l.EventsMaxBytes>>20))
	if err != nil {
		return l, err
	}
	age, err := EnvDuration("SIEM_QUEUE_MAX_AGE", l.MaxAge)
	if err != nil {
		return l, err
	}
	l.RawMaxBytes, l.EventsMaxBytes, l.MaxAge = int64(raw)<<20, int64(events)<<20, age
	return l, nil
}

// WatchQueue co minutę sprawdza zaległości konsumenta i zajętość strumienia.
// Rosnąca kolejka to sygnał, że etap nie nadąża i trzeba dodać repliki
// (roadmapa, załącznik E). Ostrzega powyżej warn, alarmuje powyżej alarm.
func WatchQueue(ctx context.Context, log *slog.Logger, js jetstream.JetStream, stream, consumer string, warn, alarm float64) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	level := slog.LevelInfo
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
					pending = info.NumPending
				}
			}
		}
		cancel()
		if err != nil {
			log.Warn("odczyt stanu kolejki nieudany", "stream", stream, "err", err)
			continue
		}
		next := slog.LevelInfo
		switch {
		case fill.Ratio >= alarm:
			next = slog.LevelError
		case fill.Ratio >= warn:
			next = slog.LevelWarn
		}
		attrs := []any{"stream", stream, "fill", round(fill.Ratio), "bytes", fill.Bytes, "pending", pending}
		switch {
		case next > slog.LevelInfo:
			log.Log(ctx, next, "kolejka rośnie – etap nie nadąża (rozważ więcej replik)", attrs...)
		case level > slog.LevelInfo:
			log.Info("kolejka wróciła do normy", attrs...)
		default:
			log.Debug("stan kolejki", attrs...)
		}
		level = next
	}
}

func round(f float64) float64 { return float64(int(f*1000)) / 1000 }
