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
	"siem/internal/server/metrics"
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

	limits, err := svc.QueueLimits()
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
		if err := bus.EnsurePipeline(ctx, js, limits); err != nil {
			return err
		}
		var err error
		cons, err = js.Consumer(ctx, bus.StreamEvents, bus.ConsumerWriter)
		return err
	}); err != nil {
		return err
	}

	p := &pipeline{w: w, log: log, seen: chwriter.NewSeen(500_000), maxRows: maxRows, m: metrics.NewWriter()}
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	go svc.WatchQueue(ctx, log, js, bus.StreamEvents, bus.ConsumerWriter, 0.5, 0.8, metrics.NewQueue())
	log.Info("zapis do ClickHouse uruchomiony", "max_rows", maxRows, "flush_every", flushEvery)
	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()
	firstPending := time.Time{}

	for ctx.Err() == nil {
		select {
		case <-statsTick.C:
			log.Info("statystyki", "rows", p.rows, "quarantine", p.quarantined, "rejected_by_db", p.rejected, "duplicates_skipped", p.dups, "insert_errors", p.errors)
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
	m       *metrics.Writer
	maxRows int

	msgs       []jetstream.Msg
	events     []model.Event
	quarantine []model.Quarantined

	rows, quarantined, rejected, dups, errors int64
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
			p.m.Duplicates.Inc()
			continue
		}
		p.events = append(p.events, e)
	}
	p.quarantine = append(p.quarantine, b.Quarantine...)
}

// flush zapisuje zgromadzone wiersze; po sukcesie potwierdza wiadomości,
// po awarii prosi o ponowne dostarczenie (nic nie ginie). Wiersze, których
// ClickHouse nie przyjmie z powodu treści, trafiają do kwarantanny.
func (p *pipeline) flush(ctx context.Context) {
	defer func() { p.msgs, p.events, p.quarantine = nil, nil, nil }()
	start := time.Now()
	defer func() { p.m.InsertDuration.Observe(time.Since(start).Seconds()) }()

	rejected, err := chwriter.Bisect(ctx, p.events, p.w.InsertEvents, func(ok []model.Event) {
		// Zapisane od razu oznaczamy – po ponownym dostarczeniu zostaną pominięte.
		for _, e := range ok {
			p.seen.Add(e.ID)
		}
		p.rows += int64(len(ok))
		p.m.Rows.Add(float64(len(ok)))
		now := time.Now()
		for _, e := range ok {
			p.m.Latency.Observe(now.Sub(e.Ingested).Seconds())
		}
	})
	quarantine := p.quarantine
	for _, r := range rejected {
		p.rejected++
		p.m.Rejected.Inc()
		p.log.Error("ClickHouse odrzucił zdarzenie – przenoszę do kwarantanny", "event_id", r.Event.ID, "err", r.Err)
		quarantine = append(quarantine, r.Quarantined())
	}
	if err == nil {
		err = p.w.InsertQuarantine(ctx, quarantine)
	}
	if err != nil {
		p.errors++
		p.m.InsertErrors.Inc()
		p.log.Error("zapis do ClickHouse nieudany – ponowię", "rows", len(p.events), "err", err)
		for _, m := range p.msgs {
			_ = m.NakWithDelay(5 * time.Second)
		}
		return
	}
	for _, m := range p.msgs {
		_ = m.Ack()
	}
	p.quarantined += int64(len(quarantine))
	p.m.Quarantined.Add(float64(len(quarantine)))
}
