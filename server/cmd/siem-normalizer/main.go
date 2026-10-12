// Command siem-normalizer czyta surowe paczki ze strumienia SIEM_RAW,
// normalizuje zdarzenia i publikuje wynik w strumieniu SIEM_EVENTS.
// Wiadomość wejściowa jest potwierdzana dopiero po zapisie wyniku.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/model"
	"siem/internal/reprocess"
	"siem/internal/svc"
	"siem/server/internal/bus"
	"siem/server/internal/ingest"
	"siem/server/internal/metrics"
	"siem/server/internal/normalize"
	"siem/server/internal/queue"
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

	limits, err := queue.Limits()
	if err != nil {
		return err
	}
	nc, js, err := bus.Connect(svc.Env("SIEM_NATS_URL", "nats://nats:4222"), "siem-normalizer")
	if err != nil {
		return err
	}
	defer nc.Close()

	// SIEM_PIPELINE=replay: kopia normalizatora dla paczek odtwarzanych
	// z archiwum (SIEM_REPLAY_RAW → SIEM_REPLAY_EVENTS).
	pl, err := bus.PipelineByName(os.Getenv("SIEM_PIPELINE"))
	if err != nil {
		return err
	}
	var cons jetstream.Consumer
	if err := svc.Retry(ctx, log, "konsument "+pl.RawStream, func() error {
		if err := pl.Ensure(ctx, js, limits); err != nil {
			return err
		}
		var err error
		cons, err = js.Consumer(ctx, pl.RawStream, pl.Normalizer)
		return err
	}); err != nil {
		return err
	}

	// Dekodery syslog zmienione w panelu (NATS KV) – podmiana bez restartu;
	// do czasu wczytania działają wbudowane.
	go normalize.WatchDecoders(ctx, js, log)
	go normalize.WatchIdentity(ctx, js, log)
	normalize.WaitConfig(ctx, 15*time.Second, log)

	// Ponowne przetwarzanie kwarantanny na zlecenie panelu – tylko ścieżka live.
	if pl.Name == bus.Live.Name {
		sub, err := nc.QueueSubscribe(reprocess.Subject, "normalizer", func(m *nats.Msg) {
			rep := handleReprocess(ctx, js, pl, m.Data)
			if rep.Error != "" {
				log.Warn("ponowne przetworzenie kwarantanny nieudane", "err", rep.Error)
			}
			b, _ := json.Marshal(rep)
			_ = m.Respond(b)
		})
		if err != nil {
			return err
		}
		defer func() { _ = sub.Drain() }()
	}

	var batches, events, quarantined atomic.Int64
	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()
	m := metrics.NewNormalizer()
	go metrics.Serve(ctx, log, svc.Env("SIEM_METRICS_ADDR", ":9100"))
	go queue.Watch(ctx, log, js, pl.RawStream, pl.Normalizer, 0.5, 0.8, metrics.NewQueue())
	workers, err := svc.EnvInt("SIEM_NORMALIZER_WORKERS", runtime.GOMAXPROCS(0))
	if err != nil {
		return err
	}
	workers = max(1, workers)
	log.Info("normalizator uruchomiony", "pipeline", pl.Name, "workers", workers)

	// Paczki są przetwarzane równolegle (etap 1.5, W1): normalizacja zajmuje
	// CPU, a publikacja czeka na potwierdzenie NATS – jedna paczka naraz
	// marnowała rdzenie. Kolejność nie ma znaczenia: każda paczka jest
	// potwierdzana osobno, a ponowienie daje duplikat odrzucany przez JetStream.
	handle := func(msg jetstream.Msg) {
		start := time.Now()
		n, q, err := process(ctx, js, pl, msg)
		switch {
		case errors.Is(err, normalize.ErrUnreadable):
			log.Error("nieczytelna paczka w kolejce – pominięta", "subject", msg.Subject(), "err", err)
			_ = msg.Term()
			m.Batches.WithLabelValues("poison").Inc()
		case err != nil:
			log.Warn("publikacja wyniku nieudana – ponowię", "err", err)
			_ = msg.NakWithDelay(5 * time.Second)
			m.Batches.WithLabelValues("retry").Inc()
		default:
			_ = msg.Ack()
			batches.Add(1)
			events.Add(int64(n))
			quarantined.Add(int64(q))
			m.Batches.WithLabelValues("ok").Inc()
			m.Events.Add(float64(n))
			m.Quarantined.Add(float64(q))
			m.Duration.Observe(time.Since(start).Seconds())
		}
	}
	work := make(chan jetstream.Msg, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for msg := range work {
				handle(msg)
			}
		})
	}
	defer func() {
		close(work)
		wg.Wait()
	}()

	for ctx.Err() == nil {
		select {
		case <-statsTick.C:
			log.Info("statystyki", "batches", batches.Load(), "events", events.Load(), "quarantined", quarantined.Load())
		default:
		}
		msgs, err := cons.Fetch(max(32, 4*workers), jetstream.FetchMaxWait(time.Second))
		if err != nil {
			log.Warn("pobranie z kolejki nieudane", "err", err)
			time.Sleep(time.Second)
			continue
		}
		for msg := range msgs.Messages() {
			work <- msg
		}
	}
	return nil
}

func process(ctx context.Context, js jetstream.JetStream, pl bus.Pipeline, msg jetstream.Msg) (events, quarantined int, err error) {
	h := msg.Headers()
	agentID := h.Get(bus.HdrAgent)
	receivedAt, terr := time.Parse(time.RFC3339Nano, h.Get(bus.HdrReceivedAt))
	if agentID == "" || terr != nil {
		return 0, 0, errors.Join(normalize.ErrUnreadable, errors.New("brak nagłówków agenta lub czasu"))
	}
	var replayID uint32
	if v := h.Get(bus.HdrReplay); v != "" {
		id, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil || id == 0 {
			return 0, 0, errors.Join(normalize.ErrUnreadable, fmt.Errorf("niepoprawny nagłówek %s: %q", bus.HdrReplay, v))
		}
		replayID = uint32(id)
	}
	gz, nb, err := normalize.Encoded(msg.Data(), agentID, receivedAt, replayID, ingest.MaxDecompressed)
	if err != nil {
		return 0, 0, err
	}
	pub := &nats.Msg{Subject: pl.EventsSubject(agentID), Data: gz, Header: nats.Header{}}
	pub.Header.Set(bus.HdrAgent, agentID)
	pub.Header.Set(bus.HdrBatch, nb.BatchID)
	pub.Header.Set(bus.HdrEncoding, "gzip")
	// Ten sam identyfikator przy ponownym przetworzeniu = duplikat odrzucony przez JetStream.
	msgID := nb.BatchID
	if replayID != 0 {
		pub.Header.Set(bus.HdrReplay, strconv.FormatUint(uint64(replayID), 10))
		msgID = fmt.Sprintf("replay-%d-%s", replayID, nb.BatchID)
	}
	if _, err := js.PublishMsg(ctx, pub, jetstream.WithMsgID(msgID)); err != nil {
		return 0, 0, err
	}
	return len(nb.Events), len(nb.Quarantine), nil
}

// handleReprocess normalizuje część zlecenia ponownego przetworzenia
// kwarantanny i publikuje odzyskane zdarzenia (paczka na agenta; ten sam
// identyfikator przy ponowieniu części – duplikat odrzucany przez JetStream).
func handleReprocess(ctx context.Context, js jetstream.JetStream, pl bus.Pipeline, data []byte) reprocess.Reply {
	var req reprocess.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return reprocess.Reply{Error: "nieczytelne żądanie: " + err.Error()}
	}
	evs, rep := normalize.Reprocess(req, time.Now())
	agents := make([]string, 0, len(evs))
	for a := range evs {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, agentID := range agents {
		nb := model.Batch{BatchID: fmt.Sprintf("reprocess-%d-%d-%s", req.Job, req.Chunk, agentID), AgentID: agentID, Events: evs[agentID]}
		raw, err := json.Marshal(nb)
		if err != nil {
			return reprocess.Reply{Error: err.Error()}
		}
		gz, err := bus.Gzip(raw)
		if err != nil {
			return reprocess.Reply{Error: err.Error()}
		}
		pub := &nats.Msg{Subject: pl.EventsSubject(agentID), Data: gz, Header: nats.Header{}}
		pub.Header.Set(bus.HdrAgent, agentID)
		pub.Header.Set(bus.HdrBatch, nb.BatchID)
		pub.Header.Set(bus.HdrEncoding, "gzip")
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err = js.PublishMsg(pctx, pub, jetstream.WithMsgID(nb.BatchID))
		cancel()
		if err != nil {
			return reprocess.Reply{Error: "publikacja zdarzeń: " + err.Error()}
		}
	}
	return rep
}
