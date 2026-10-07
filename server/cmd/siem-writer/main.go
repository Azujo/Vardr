// Command siem-writer czyta znormalizowane paczki ze strumienia SIEM_EVENTS
// i zapisuje je do ClickHouse dużymi paczkami. Wiadomości są potwierdzane
// dopiero po udanym INSERT.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/chwriter"
	"siem/server/internal/metrics"
	"siem/server/internal/model"
	"siem/server/internal/queue"
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

	limits, err := queue.Limits()
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

	p := &pipeline{w: w, log: log, seen: chwriter.NewSeen(500_000), m: metrics.NewWriter()}
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	go queue.Watch(ctx, log, js, bus.StreamEvents, bus.ConsumerWriter, 0.5, 0.8, metrics.NewQueue())
	log.Info("zapis do ClickHouse uruchomiony", "max_rows", maxRows, "flush_every", flushEvery)
	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()

	// Zapis do ClickHouse odbywa się w tle (etap 1.5): w czasie INSERT-u
	// kolejna paczka jest już pobierana i dekodowana. Co najwyżej jedna
	// paczka czeka na zapis, więc pamięć i liczba niepotwierdzonych
	// wiadomości pozostają ograniczone.
	insCtx, insCancel := context.WithCancel(context.Background())
	defer insCancel()
	toInsert := make(chan *pending, 1)
	inserterDone := make(chan struct{})
	go func() {
		defer close(inserterDone)
		for r := range toInsert {
			p.flush(insCtx, r)
		}
	}()

	cur, firstPending := &pending{}, time.Time{}
	for ctx.Err() == nil {
		select {
		case <-statsTick.C:
			log.Info("statystyki", "rows", p.rows.Load(), "quarantine", p.quarantined.Load(), "rejected_by_db", p.rejected.Load(),
				"duplicates_skipped", p.dups.Load(), "insert_errors", p.errors.Load())
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
			p.add(cur, msg)
		}
		if len(cur.msgs) > 0 && (len(cur.events)+len(cur.quarantine) >= maxRows || time.Since(firstPending) >= flushEvery) {
			select {
			case toInsert <- cur:
				cur, firstPending = &pending{}, time.Time{}
			case <-ctx.Done():
			}
		}
	}
	// Zatrzymanie: dopisujemy to, co zebrane, i czekamy na zapis (maks. 15 s).
	if len(cur.msgs) > 0 {
		toInsert <- cur
	}
	close(toInsert)
	select {
	case <-inserterDone:
	case <-time.After(15 * time.Second):
		insCancel()
		<-inserterDone
	}
	return nil
}

// pending to wiersze zebrane z wiadomości kolejki, zapisywane jednym INSERT-em.
type pending struct {
	msgs       []jetstream.Msg
	events     []model.Event
	quarantine []model.Quarantined
}

type pipeline struct {
	w   *chwriter.Writer
	log *slog.Logger
	m   *metrics.Writer

	// add (pętla pobierania) i flush (zapis w tle) działają równolegle.
	seenMu sync.Mutex
	seen   *chwriter.Seen

	rows, quarantined, rejected, dups, errors atomic.Int64
}

func (p *pipeline) add(cur *pending, msg jetstream.Msg) {
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
	cur.msgs = append(cur.msgs, msg)
	p.seenMu.Lock()
	for _, e := range b.Events {
		if p.seen.Has(e.ID) {
			p.dups.Add(1)
			p.m.Duplicates.Inc()
			continue
		}
		cur.events = append(cur.events, e)
	}
	p.seenMu.Unlock()
	cur.quarantine = append(cur.quarantine, b.Quarantine...)
}

// flush zapisuje zgromadzone wiersze; po sukcesie potwierdza wiadomości,
// po awarii prosi o ponowne dostarczenie (nic nie ginie). Wiersze, których
// ClickHouse nie przyjmie z powodu treści, trafiają do kwarantanny.
func (p *pipeline) flush(ctx context.Context, r *pending) {
	start := time.Now()
	defer func() { p.m.InsertDuration.Observe(time.Since(start).Seconds()) }()

	rejected, err := chwriter.Bisect(ctx, r.events, p.w.InsertEvents, func(ok []model.Event) {
		// Zapisane od razu oznaczamy – po ponownym dostarczeniu zostaną pominięte.
		p.seenMu.Lock()
		for _, e := range ok {
			p.seen.Add(e.ID)
		}
		p.seenMu.Unlock()
		p.rows.Add(int64(len(ok)))
		p.m.Rows.Add(float64(len(ok)))
		now := time.Now()
		for _, e := range ok {
			p.m.Latency.Observe(now.Sub(e.Ingested).Seconds())
		}
	})
	quarantine := r.quarantine
	for _, rj := range rejected {
		p.rejected.Add(1)
		p.m.Rejected.Inc()
		p.log.Error("ClickHouse odrzucił zdarzenie – przenoszę do kwarantanny", "event_id", rj.Event.ID, "err", rj.Err)
		quarantine = append(quarantine, rj.Quarantined())
	}
	if err == nil {
		err = p.w.InsertQuarantine(ctx, quarantine)
	}
	if err != nil {
		p.errors.Add(1)
		p.m.InsertErrors.Inc()
		p.log.Error("zapis do ClickHouse nieudany – ponowię", "rows", len(r.events), "err", err)
		for _, m := range r.msgs {
			_ = m.NakWithDelay(5 * time.Second)
		}
		return
	}
	for _, m := range r.msgs {
		_ = m.Ack()
	}
	p.quarantined.Add(int64(len(quarantine)))
	p.m.Quarantined.Add(float64(len(quarantine)))
}
