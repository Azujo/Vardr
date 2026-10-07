// Package archiver zapisuje surowe paczki z kolejki SIEM_RAW do archiwum
// NIS2 (Urd). Wiadomość jest potwierdzana dopiero, gdy segment z nią jest
// trwale zapisany na dysku i zarejestrowany w spisie.
package archiver

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/urd"
	"siem/server/internal/bus"
	"siem/server/internal/metrics"
)

// Msg to część jetstream.Msg używana przez archiwizator.
type Msg interface {
	Data() []byte
	Headers() nats.Header
	Subject() string
	Metadata() (*jetstream.MsgMetadata, error)
	Ack() error
	NakWithDelay(time.Duration) error
}

// Config to parametry archiwizacji.
type Config struct {
	SegmentMaxBytes int64         // zamknięcie segmentu po przekroczeniu rozmiaru
	SegmentMaxAge   time.Duration // … albo po tym czasie (opóźnienie potwierdzeń)
	// ExcludeAgents: prefiksy identyfikatorów agentów, których paczki nie
	// trafiają do archiwum (np. agt-load- generatora ruchu). Paczka jest
	// potwierdzana bez zapisu.
	ExcludeAgents []string
	// Progi miejsca na dysku archiwum: poniżej Min… archiwizacja jest
	// wstrzymywana (paczki czekają w kolejce), poniżej Warn… ostrzeżenie.
	MinFreeBytes    uint64
	MinFreePercent  float64
	WarnFreePercent float64
}

// Archiver dopisuje paczki do bieżącego segmentu i zamyka godziny manifestami.
// Nie jest bezpieczny dla wielu gorutyn – działa w pętli pobierania.
type Archiver struct {
	A   *urd.Archive
	Cfg Config
	Log *slog.Logger
	M   *metrics.Archiver

	cur       *urd.SegmentWriter
	pending   []Msg
	sealedFor time.Time // godzina, dla której poprzednie godziny mają manifesty
	sealRetry time.Time

	Health    *Health
	diskCheck time.Time
	diskWarn  time.Time
	paused    string
}

// Add dopisuje wiadomość do bieżącego segmentu (bez potwierdzenia).
func (r *Archiver) Add(ctx context.Context, msg Msg) error {
	if r.excluded(msg.Headers().Get(bus.HdrAgent)) {
		r.M.Skipped.Inc()
		return msg.Ack()
	}
	now := r.A.Now().UTC()
	if r.cur != nil && !r.cur.Hour().Equal(now.Truncate(time.Hour)) {
		if err := r.Flush(ctx); err != nil {
			_ = msg.NakWithDelay(5 * time.Second)
			return err
		}
	}
	if r.cur == nil {
		w, err := r.A.OpenSegment()
		if err != nil {
			r.M.Errors.WithLabelValues("open").Inc()
			_ = msg.NakWithDelay(5 * time.Second)
			return err
		}
		r.cur = w
	}
	h := msg.Headers()
	meta := urd.RecordMeta{
		Agent:    h.Get(bus.HdrAgent),
		Batch:    h.Get(bus.HdrBatch),
		Encoding: h.Get(bus.HdrEncoding),
		Subject:  msg.Subject(),
	}
	if t, err := time.Parse(time.RFC3339Nano, h.Get(bus.HdrReceivedAt)); err == nil {
		meta.ReceivedAt = t.UTC()
	} else {
		meta.ReceivedAt = now
	}
	if md, err := msg.Metadata(); err == nil {
		meta.StreamSeq = md.Sequence.Stream
	}
	if err := r.cur.Add(meta, msg.Data()); err != nil {
		// Zapis na dysk nieudany: cały segment jest porzucany, a wiadomości
		// wracają do kolejki.
		r.M.Errors.WithLabelValues("write").Inc()
		r.pending = append(r.pending, msg)
		r.abort()
		return err
	}
	r.pending = append(r.pending, msg)
	return nil
}

// Tick zamyka segment po przekroczeniu rozmiaru, wieku lub godziny
// i tworzy manifesty zakończonych godzin. Wywoływany po każdym pobraniu.
func (r *Archiver) Tick(ctx context.Context) error {
	now := r.A.Now().UTC()
	hour := now.Truncate(time.Hour)
	if r.cur != nil && (r.cur.Bytes() >= r.Cfg.SegmentMaxBytes || r.cur.Age(now) >= r.Cfg.SegmentMaxAge ||
		!r.cur.Hour().Equal(hour)) {
		if err := r.Flush(ctx); err != nil {
			return err
		}
	}
	if r.sealedFor.Equal(hour) || now.Before(r.sealRetry) {
		return nil
	}
	// Otwarty segment z poprzedniej godziny zostałby pominięty w manifeście.
	if r.cur != nil && !r.cur.Hour().Equal(hour) {
		return nil
	}
	n, err := r.A.Seal(ctx)
	if err != nil {
		r.M.Errors.WithLabelValues("seal").Inc()
		r.sealRetry = now.Add(30 * time.Second)
		return err
	}
	r.sealedFor = hour
	if n > 0 {
		r.M.Manifests.Add(float64(n))
		r.Log.Info("zamknięto godziny archiwum", "manifests", n)
	}
	return nil
}

// Flush zatwierdza bieżący segment i potwierdza jego wiadomości.
func (r *Archiver) Flush(ctx context.Context) error {
	if r.cur == nil {
		return nil
	}
	w, msgs := r.cur, r.pending
	r.cur, r.pending = nil, nil
	seg, err := w.Commit(ctx)
	if err != nil {
		r.M.Errors.WithLabelValues("commit").Inc()
		for _, m := range msgs {
			_ = m.NakWithDelay(5 * time.Second)
		}
		return err
	}
	for _, m := range msgs {
		_ = m.Ack()
	}
	r.M.Batches.Add(float64(seg.Records))
	r.M.Bytes.Add(float64(seg.Bytes))
	r.M.Segments.Inc()
	r.M.LastSegment.Set(float64(time.Now().Unix()))
	return nil
}

func (r *Archiver) abort() {
	if r.cur != nil {
		r.cur.Abort()
	}
	for _, m := range r.pending {
		_ = m.NakWithDelay(5 * time.Second)
	}
	r.cur, r.pending = nil, nil
}

// Close zatwierdza otwarty segment przy zatrzymaniu usługi.
func (r *Archiver) Close(ctx context.Context) error { return r.Flush(ctx) }

// StateStore zapisuje stan archiwizatora dla panelu i przekazuje zlecenia
// weryfikacji (implementuje urd.PG).
type StateStore interface {
	SaveState(ctx context.Context, s urd.ArchiverState) error
	TakeVerifyRequest(ctx context.Context) (by string, ok bool, err error)
}

// MaintainConfig to parametry pracy okresowej.
type MaintainConfig struct {
	Retention    time.Duration
	VerifyEvery  time.Duration
	FirstVerify  time.Duration // pierwsza weryfikacja po starcie
	VerifyBudget int64         // bajty czytane w całości w jednym przebiegu (0 = wszystko)
	State        StateStore    // nil = bez stanu dla panelu
	StateBase    urd.ArchiverState
	Health       *Health // stan dysku z pętli archiwizatora
}

// Maintain co minutę zapisuje stan dla panelu, usuwa dane po retencji
// i weryfikuje archiwum (okresowo i na zlecenie z panelu). Działa w osobnej
// gorutynie – Expire i Verify nie mogą się na siebie nakładać.
func Maintain(ctx context.Context, a *urd.Archive, log *slog.Logger, m *metrics.Archiver, c MaintainConfig) {
	verifyAt := time.Now().Add(c.FirstVerify)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastExpire := time.Time{}
	for {
		if c.State != nil {
			st := c.StateBase
			st.HeartbeatAt = time.Now().UTC()
			free, total, paused := c.Health.Get()
			st.DiskFreeBytes, st.DiskTotalBytes, st.Paused = int64(free), int64(total), paused
			if err := c.State.SaveState(ctx, st); err != nil && ctx.Err() == nil {
				log.Warn("zapis stanu archiwizatora nieudany", "err", err)
			}
			if by, ok, err := c.State.TakeVerifyRequest(ctx); err != nil && ctx.Err() == nil {
				log.Warn("odczyt zleceń weryfikacji nieudany", "err", err)
			} else if ok {
				log.Info("weryfikacja zlecona z panelu", "by", by)
				verifyAt = time.Now()
			}
		}
		if time.Since(lastExpire) >= time.Hour {
			lastExpire = time.Now()
			if n, err := a.Expire(ctx, c.Retention); err != nil {
				m.Errors.WithLabelValues("expire").Inc()
				log.Error("usuwanie danych po retencji nieudane", "err", err)
			} else if n > 0 {
				log.Info("usunięto dane po retencji", "hours", n, "retention", c.Retention.String())
			}
		}
		if !time.Now().Before(verifyAt) {
			verifyAt = time.Now().Add(c.VerifyEvery)
			RunVerify(ctx, a, log, m, urd.VerifyOptions{BudgetBytes: c.VerifyBudget})
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// RunVerify weryfikuje archiwum i zapisuje wynik w spisie.
func RunVerify(ctx context.Context, a *urd.Archive, log *slog.Logger, m *metrics.Archiver, opt urd.VerifyOptions) urd.Verification {
	v := a.Verify(ctx, opt)
	if _, err := a.Cat.SaveVerification(context.WithoutCancel(ctx), v); err != nil {
		log.Error("zapis wyniku weryfikacji nieudany", "err", err)
	}
	ok := 0.0
	if v.OK {
		ok = 1
	}
	m.VerifyOK.Set(ok)
	m.VerifyProblem.Set(float64(len(v.Problems)))
	m.LastVerify.Set(float64(time.Now().Unix()))
	args := []any{"manifests", v.Manifests, "segments", v.Segments, "full_manifests", v.FullManifests,
		"unverified", v.Unverified, "hashed_batches", v.Records, "hashed_bytes", v.Bytes,
		"took", v.FinishedAt.Sub(v.StartedAt).Round(time.Millisecond).String()}
	if v.OK {
		log.Info("weryfikacja archiwum: zgodne", args...)
	} else {
		log.Error("weryfikacja archiwum: NIEZGODNOŚCI", append(args, "problems", v.Problems)...)
	}
	return v
}
