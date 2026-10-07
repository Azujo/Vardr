package archiver

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/urd"
	"siem/server/internal/bus"
)

// ReplayStore to zlecenia odtworzenia w spisie (implementuje urd.PG).
type ReplayStore interface {
	ClaimReplay(ctx context.Context) (urd.ReplayJob, bool, error)
	ReplayProgress(ctx context.Context, id int64, st urd.ReplayStats) error
	FinishReplay(ctx context.Context, j urd.ReplayJob) error
	FailInterruptedReplays(ctx context.Context) (int64, error)
}

// Publisher to część jetstream.JetStream używana do odtwarzania.
type Publisher interface {
	PublishMsg(ctx context.Context, msg *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// Replayer odtwarza paczki z archiwum do ścieżki replay (osobne strumienie,
// normalizator i writer, tabela siem.events_replay).
type Replayer struct {
	A     *urd.Archive
	Store ReplayStore
	Pub   Publisher
	Log   *slog.Logger
	Lock  *sync.Mutex // wspólna z retencją i eksportem
	// RetryWait: przerwa po odmowie zapisu (pełny strumień odtwarzania).
	RetryWait time.Duration
}

// Run sprawdza zlecenia co 15 s.
func (r *Replayer) Run(ctx context.Context) {
	if n, err := r.Store.FailInterruptedReplays(ctx); err != nil {
		r.Log.Warn("oznaczanie przerwanych odtworzeń nieudane", "err", err)
	} else if n > 0 {
		r.Log.Warn("odtworzenia przerwane restartem oznaczone jako nieudane", "count", n)
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		for ctx.Err() == nil {
			j, ok, err := r.Store.ClaimReplay(ctx)
			if err != nil {
				r.Log.Warn("odczyt zleceń odtworzenia nieudany", "err", err)
				break
			}
			if !ok {
				break
			}
			r.Log.Info("odtworzenie z archiwum: start", "id", j.ID, "by", j.RequestedBy, "agents", j.Agents,
				"from", j.From.UTC().Format(time.RFC3339), "to", j.To.UTC().Format(time.RFC3339))
			j = r.runJob(ctx, j)
			if err := r.Store.FinishReplay(context.WithoutCancel(ctx), j); err != nil {
				r.Log.Error("zapis wyniku odtworzenia nieudany", "id", j.ID, "err", err)
			}
			if j.Status == urd.ReplayDone {
				r.Log.Info("odtworzenie z archiwum: gotowe", "id", j.ID, "batches", j.Batches, "skipped", j.Skipped)
			} else {
				r.Log.Error("odtworzenie z archiwum nieudane", "id", j.ID, "err", j.Error)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (r *Replayer) runJob(ctx context.Context, j urd.ReplayJob) urd.ReplayJob {
	r.Lock.Lock()
	defer r.Lock.Unlock()
	id := strconv.FormatInt(j.ID, 10)
	lastProgress := time.Now()
	st, err := r.A.Replay(ctx, j.From, j.To, j.Agents, func(m urd.RecordMeta, payload []byte) error {
		msg := &nats.Msg{Subject: bus.Replay.RawSubject(m.Agent), Data: payload, Header: nats.Header{}}
		msg.Header.Set(bus.HdrAgent, m.Agent)
		msg.Header.Set(bus.HdrBatch, m.Batch)
		msg.Header.Set(bus.HdrReceivedAt, m.ReceivedAt.UTC().Format(time.RFC3339Nano))
		if m.Encoding != "" {
			msg.Header.Set(bus.HdrEncoding, m.Encoding)
		}
		msg.Header.Set(bus.HdrReplay, id)
		// Ta sama paczka w archiwum dwa razy (dostarczenie „co najmniej raz”)
		// zostanie odtworzona raz – JetStream odrzuci duplikat.
		return r.publish(ctx, msg, fmt.Sprintf("replay-%d-%s-%s", j.ID, m.Agent, m.Batch))
	}, func(st urd.ReplayStats) {
		if time.Since(lastProgress) >= 5*time.Second {
			lastProgress = time.Now()
			if err := r.Store.ReplayProgress(ctx, j.ID, st); err != nil {
				r.Log.Warn("zapis postępu odtworzenia nieudany", "id", j.ID, "err", err)
			}
		}
	})
	j.Batches, j.Skipped, j.Bytes = st.Batches, st.Skipped, st.Bytes
	if err != nil {
		j.Status, j.Error = urd.ReplayFailed, err.Error()
		return j
	}
	j.Status = urd.ReplayDone
	return j
}

// publish ponawia zapis, gdy strumień odtwarzania jest pełny (odtwarzanie
// czeka na normalizator i writer zamiast odrzucać paczki).
func (r *Replayer) publish(ctx context.Context, msg *nats.Msg, msgID string) error {
	wait := r.RetryWait
	if wait == 0 {
		wait = 2 * time.Second
	}
	for attempt := 1; ; attempt++ {
		_, err := r.Pub.PublishMsg(ctx, msg, jetstream.WithMsgID(msgID))
		if err == nil {
			return nil
		}
		if !bus.IsQueueFull(err) && attempt >= 10 {
			return fmt.Errorf("publikacja do ścieżki odtwarzania: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
