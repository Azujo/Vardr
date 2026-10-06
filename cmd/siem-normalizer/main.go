// Command siem-normalizer czyta surowe paczki ze strumienia SIEM_RAW,
// normalizuje zdarzenia i publikuje wynik w strumieniu SIEM_EVENTS.
// Wiadomość wejściowa jest potwierdzana dopiero po zapisie wyniku.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/contract"
	"siem/internal/server/bus"
	"siem/internal/server/ingest"
	"siem/internal/server/normalize"
	"siem/internal/server/svc"
)

func main() {
	log := svc.Logger("normalizer")
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
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-normalizer")
	if err != nil {
		return err
	}
	defer nc.Close()

	var cons jetstream.Consumer
	if err := svc.Retry(ctx, log, "konsument SIEM_RAW", func() error {
		if err := bus.EnsureStreams(ctx, js, retention); err != nil {
			return err
		}
		var err error
		cons, err = js.CreateOrUpdateConsumer(ctx, bus.StreamRaw, jetstream.ConsumerConfig{
			Durable:       "normalizer",
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       time.Minute,
			MaxAckPending: 256,
		})
		return err
	}); err != nil {
		return err
	}

	var batches, events, quarantined atomic.Int64
	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()
	log.Info("normalizator uruchomiony")

	for ctx.Err() == nil {
		select {
		case <-statsTick.C:
			log.Info("statystyki", "batches", batches.Load(), "events", events.Load(), "quarantined", quarantined.Load())
		default:
		}
		msgs, err := cons.Fetch(32, jetstream.FetchMaxWait(time.Second))
		if err != nil {
			log.Warn("pobranie z kolejki nieudane", "err", err)
			time.Sleep(time.Second)
			continue
		}
		for msg := range msgs.Messages() {
			n, q, err := process(ctx, js, msg)
			switch {
			case errors.Is(err, errPoison):
				log.Error("nieczytelna paczka w kolejce – pominięta", "subject", msg.Subject(), "err", err)
				_ = msg.Term()
			case err != nil:
				log.Warn("publikacja wyniku nieudana – ponowię", "err", err)
				_ = msg.NakWithDelay(5 * time.Second)
			default:
				_ = msg.Ack()
				batches.Add(1)
				events.Add(int64(n))
				quarantined.Add(int64(q))
			}
		}
	}
	return nil
}

var errPoison = errors.New("nieczytelna wiadomość")

func process(ctx context.Context, js jetstream.JetStream, msg jetstream.Msg) (events, quarantined int, err error) {
	h := msg.Headers()
	agentID := h.Get(bus.HdrAgent)
	receivedAt, terr := time.Parse(time.RFC3339Nano, h.Get(bus.HdrReceivedAt))
	if agentID == "" || terr != nil {
		return 0, 0, errors.Join(errPoison, errors.New("brak nagłówków agenta lub czasu"))
	}
	data, err := bus.Gunzip(msg.Data(), ingest.MaxDecompressed)
	if err != nil {
		return 0, 0, errors.Join(errPoison, err)
	}
	var b contract.Batch
	if err := json.Unmarshal(data, &b); err != nil {
		return 0, 0, errors.Join(errPoison, err)
	}

	nb := normalize.Batch(b, agentID, receivedAt)
	out, err := json.Marshal(nb)
	if err != nil {
		return 0, 0, errors.Join(errPoison, err)
	}
	gz, err := bus.Gzip(out)
	if err != nil {
		return 0, 0, err
	}
	pub := &nats.Msg{Subject: bus.EventsSubject(agentID), Data: gz, Header: nats.Header{}}
	pub.Header.Set(bus.HdrAgent, agentID)
	pub.Header.Set(bus.HdrBatch, b.BatchID)
	pub.Header.Set(bus.HdrEncoding, "gzip")
	// Ten sam identyfikator przy ponownym przetworzeniu = duplikat odrzucony przez JetStream.
	if _, err := js.PublishMsg(ctx, pub, jetstream.WithMsgID(b.BatchID)); err != nil {
		return 0, 0, err
	}
	return len(nb.Events), len(nb.Quarantine), nil
}
