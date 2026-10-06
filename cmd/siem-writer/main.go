// Command siem-writer czyta znormalizowane paczki ze strumienia SIEM_EVENTS
// i zapisuje je do ClickHouse dużymi paczkami. Wiadomości są potwierdzane
// dopiero po udanym INSERT.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/server/bus"
	"siem/internal/server/chwriter"
	"siem/internal/server/model"
	"siem/internal/server/svc"
)

func main() {
	log := svc.Logger("writer")
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
	maxRows, err := svc.EnvInt("SIEM_WRITER_MAX_ROWS", 20000)
	if err != nil {
		return err
	}
	flushEvery, err := svc.EnvDuration("SIEM_WRITER_FLUSH", time.Second)
	if err != nil {
		return err
	}

	var w *chwriter.Writer
	if err := svc.Retry(ctx, log, "połączenie z ClickHouse", func() error {
		var err error
		w, err = chwriter.Open(ctx, svc.Env("SIEM_CLICKHOUSE_ADDR", "clickhouse:9000"),
			svc.MustEnv(log, "SIEM_CLICKHOUSE_USER"), svc.MustEnv(log, "SIEM_CLICKHOUSE_PASSWORD"))
		return err
	}); err != nil {
		return err
	}

	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-writer")
	if err != nil {
		return err
	}
	defer nc.Close()
	var cons jetstream.Consumer
	if err := svc.Retry(ctx, log, "konsument SIEM_EVENTS", func() error {
		if err := bus.EnsureStreams(ctx, js, retention); err != nil {
			return err
		}
		var err error
		cons, err = js.CreateOrUpdateConsumer(ctx, bus.StreamEvents, jetstream.ConsumerConfig{
			Durable:       "clickhouse-writer",
			AckPolicy:     jetstream.AckExplicitPolicy,
			AckWait:       2 * time.Minute,
			MaxAckPending: 1024,
		})
		return err
	}); err != nil {
		return err
	}

	p := &pipeline{w: w, log: log, seen: chwriter.NewSeen(500_000), maxRows: maxRows}
	log.Info("zapis do ClickHouse uruchomiony", "max_rows", maxRows, "flush_every", flushEvery)
	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()
	firstPending := time.Time{}

	for ctx.Err() == nil {
		select {
		case <-statsTick.C:
			log.Info("statystyki", "rows", p.rows, "quarantine", p.quarantined, "duplicates_skipped", p.dups, "insert_errors", p.errors)
		default:
		}
		msgs, err := cons.Fetch(64, jetstream.FetchMaxWait(flushEvery/2))
		if err != nil {
			log.Warn("pobranie z kolejki nieudane", "err", err)
			time.Sleep(time.Second)
			continue
		}
		for msg := range msgs.Messages() {
			if firstPending.IsZero() {
				firstPending = time.Now()
			}
			p.add(msg)
		}
		if len(p.msgs) > 0 && (len(p.events)+len(p.quarantine) >= maxRows || time.Since(firstPending) >= flushEvery) {
			p.flush(ctx)
			firstPending = time.Time{}
		}
	}
	if len(p.msgs) > 0 {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p.flush(shutdown)
		cancel()
	}
	return nil
}

type pipeline struct {
	w       *chwriter.Writer
	log     *slog.Logger
	seen    *chwriter.Seen
	maxRows int

	msgs       []jetstream.Msg
	events     []model.Event
	quarantine []model.Quarantined

	rows, quarantined, dups, errors int64
}

func (p *pipeline) add(msg jetstream.Msg) {
	data, err := bus.Gunzip(msg.Data(), 256<<20)
	var b model.Batch
	if err == nil {
		err = json.Unmarshal(data, &b)
	}
	if err != nil {
		p.log.Error("nieczytelna wiadomość w SIEM_EVENTS – pominięta", "subject", msg.Subject(), "err", err)
		_ = msg.Term()
		return
	}
	p.msgs = append(p.msgs, msg)
	for _, e := range b.Events {
		if p.seen.Has(e.ID) {
			p.dups++
			continue
		}
		p.events = append(p.events, e)
	}
	p.quarantine = append(p.quarantine, b.Quarantine...)
}

// flush zapisuje zgromadzone wiersze; po sukcesie potwierdza wiadomości,
// po błędzie prosi o ponowne dostarczenie (nic nie ginie).
func (p *pipeline) flush(ctx context.Context) {
	err := p.w.Insert(ctx, p.events, p.quarantine)
	if err != nil {
		p.errors++
		p.log.Error("zapis do ClickHouse nieudany – ponowię", "rows", len(p.events), "err", err)
		for _, m := range p.msgs {
			_ = m.NakWithDelay(5 * time.Second)
		}
	} else {
		for _, e := range p.events {
			p.seen.Add(e.ID)
		}
		for _, m := range p.msgs {
			_ = m.Ack()
		}
		p.rows += int64(len(p.events))
		p.quarantined += int64(len(p.quarantine))
	}
	p.msgs, p.events, p.quarantine = nil, nil, nil
}
