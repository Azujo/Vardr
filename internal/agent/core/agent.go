// Package core łączy źródła, paczkowanie, wysyłkę i zapis pozycji odczytu.
//
// Gwarancja dostarczania: pozycja kanału jest zapisywana na dysku dopiero po
// potwierdzeniu paczki przez serwer. Restart w dowolnym momencie powoduje
// najwyżej ponowne wysłanie zdarzeń (serwer deduplikuje po id), nigdy lukę.
package core

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"siem/internal/agent/source"
	"siem/internal/agent/state"
	"siem/internal/agent/status"
	"siem/internal/agent/throttle"
	"siem/internal/contract"
)

// Sender wysyła paczkę; zwraca błąd tylko przy anulowaniu kontekstu.
type Sender interface {
	Send(ctx context.Context, b *contract.Batch) error
}

// StateStore zapisuje potwierdzone pozycje.
type StateStore interface {
	Load() (state.State, error)
	Save(state.State) error
}

// Options konfiguruje rdzeń agenta.
type Options struct {
	AgentID       string
	MaxEvents     int
	MaxBytes      int
	FlushInterval time.Duration
	// Filters: kanał → dozwolone Event ID. Stosowane tylko dla kanałów,
	// których listy nie dało się wyrazić w zapytaniu XPath.
	Filters    map[string]map[uint32]bool
	RetryDelay func(err error) time.Duration
	StatsEvery time.Duration
	// MaxEPS ogranicza liczbę wysyłanych zdarzeń na sekundę (0 = brak).
	// Nadmiar czeka w dzienniku Windows – rośnie opóźnienie, nie ginie nic.
	MaxEPS int
	// LagWarn: próg opóźnienia (czas odczytu − czas wystąpienia), po którym
	// agent ostrzega, że nie nadąża (np. przez zbyt ciasny kaganiec).
	LagWarn time.Duration
	// MaxEventBytes: dłuższe zdarzenia są przycinane (0 = brak limitu).
	MaxEventBytes int
	// Status (opcjonalny) otrzymuje stan kanałów i liczniki.
	Status *status.Tracker
	// ClassifyError zamienia błąd źródła na stan kanału (status.Channel*).
	ClassifyError func(error) string
}

// Agent to rdzeń agenta.
type Agent struct {
	opts    Options
	sources []source.Source
	sender  Sender
	store   StateStore
	log     *slog.Logger

	read, filtered, sent, truncated atomic.Int64
	eps                             *throttle.Limiter
}

// New tworzy agenta.
func New(opts Options, sources []source.Source, sender Sender, store StateStore, log *slog.Logger) *Agent {
	if opts.RetryDelay == nil {
		opts.RetryDelay = func(error) time.Duration { return 10 * time.Second }
	}
	if opts.StatsEvery == 0 {
		opts.StatsEvery = time.Minute
	}
	if opts.LagWarn == 0 {
		opts.LagWarn = 5 * time.Minute
	}
	if opts.ClassifyError == nil {
		opts.ClassifyError = func(error) string { return status.ChannelError }
	}
	a := &Agent{opts: opts, sources: sources, sender: sender, store: store, log: log,
		eps: throttle.New(float64(opts.MaxEPS), float64(opts.MaxEPS))}
	opts.Status.AddProbe(func(s *status.Status) {
		s.Counters.Read = a.read.Load()
		s.Counters.Filtered = a.filtered.Load()
		s.Counters.Truncated = a.truncated.Load()
		s.Throttle.EPS = a.eps.Waited()
	})
	return a
}

// eventOverhead to przybliżony narzut JSON na zdarzenie poza polem raw.
const eventOverhead = 256

// Run działa do anulowania kontekstu.
func (a *Agent) Run(ctx context.Context) error {
	st, err := a.store.Load()
	if err != nil {
		return err
	}
	a.log.Info("agent uruchomiony", "sources", len(a.sources), "resumed_channels", len(st.Channels))

	ctx, cancel := context.WithCancel(ctx)

	// Bufor kanału = maks. jedna paczka „w drodze”. Gdy wysyłka stoi,
	// czytniki blokują się, a niewysłane zdarzenia czekają w dzienniku Windows.
	recs := make(chan source.Record, a.opts.MaxEvents)
	var wg sync.WaitGroup
	for _, src := range a.sources {
		start := source.Position{}
		if cs, ok := st.Channels[src.Channel()]; ok {
			start = source.Position{RecordID: cs.RecordID, Valid: true}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.runSource(ctx, src, start, recs)
		}()
	}
	defer func() {
		cancel()
		wg.Wait()
	}()

	b := &batcher{agent: a, st: st, lastSeen: maps.Clone(st.Channels)}
	flushTick := time.NewTicker(a.opts.FlushInterval)
	defer flushTick.Stop()
	statsTick := time.NewTicker(a.opts.StatsEvery)
	defer statsTick.Stop()

	for {
		select {
		case <-ctx.Done():
			b.logStats()
			return nil
		case rec := <-recs:
			if err := b.add(ctx, rec); err != nil {
				return ignoreCanceled(err)
			}
		case <-flushTick.C:
			if err := b.flush(ctx); err != nil {
				return ignoreCanceled(err)
			}
		case <-statsTick.C:
			b.logStats()
		}
	}
}

func (a *Agent) runSource(ctx context.Context, src source.Source, start source.Position, out chan<- source.Record) {
	pos := start
	for {
		a.opts.Status.ChannelState(src.Channel(), status.ChannelStarting, "")
		var err error
		pos, err = src.Run(ctx, pos, out)
		if ctx.Err() != nil {
			return
		}
		a.opts.Status.ChannelState(src.Channel(), a.opts.ClassifyError(err), err.Error())
		delay := a.opts.RetryDelay(err)
		a.log.Warn("źródło zatrzymane, ponowię", "channel", src.Channel(), "err", err, "retry_in", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}
}

// logStats loguje liczniki i maksymalne opóźnienie od poprzedniego wpisu.
func (b *batcher) logStats() {
	a := b.agent
	attrs := []any{"read", a.read.Load(), "filtered", a.filtered.Load(), "sent_accepted", a.sent.Load(),
		"lag_max", b.maxLag.Round(time.Millisecond), "eps_throttled", a.eps.Waited().Round(time.Millisecond)}
	if b.maxLag > a.opts.LagWarn {
		a.log.Warn("agent nie nadąża za dziennikiem – sprawdź limity", attrs...)
	} else {
		a.log.Info("statystyki", attrs...)
	}
	b.maxLag = 0
}

// batcher zbiera zdarzenia w paczkę. Działa w jednej gorutynie.
type batcher struct {
	agent    *Agent
	st       state.State                   // potwierdzony stan (to, co na dysku)
	lastSeen map[string]state.ChannelState // ostatni odczytany rekord (wykrywanie resetu numeracji)
	pending  []contract.Event
	bytes    int
	advance  map[string]state.ChannelState // pozycje do zapisania po potwierdzeniu
	maxLag   time.Duration                 // maks. opóźnienie odczytu od ostatnich statystyk
}

func (b *batcher) add(ctx context.Context, rec source.Record) error {
	a := b.agent
	a.read.Add(1)
	var lag time.Duration
	if !rec.CreatedAt.IsZero() {
		lag = rec.ReadAt.Sub(rec.CreatedAt)
		if lag > b.maxLag {
			b.maxLag = lag
		}
	}
	a.opts.Status.ChannelRead(rec.Channel, rec.RecordID, rec.ReadAt, lag)

	cs := b.lastSeen[rec.Channel]
	if cs.RecordID != 0 && rec.RecordID < cs.RecordID {
		// Numeracja spadła: dziennik został wyczyszczony lub odtworzony.
		cs.Generation++
		a.log.Warn("wykryto reset numeracji dziennika, nowa generacja",
			"channel", rec.Channel, "previous_record", cs.RecordID, "record", rec.RecordID, "generation", cs.Generation)
	}
	cs.RecordID = rec.RecordID
	b.lastSeen[rec.Channel] = cs

	if allowed, ok := a.opts.Filters[rec.Channel]; ok && (!rec.HasEventID || !allowed[rec.EventID]) {
		a.filtered.Add(1)
		b.markAdvance(rec.Channel, cs)
		return nil
	}

	if err := a.eps.Wait(ctx, 1); err != nil {
		return err
	}
	ev := contract.Event{
		Source: "wineventlog:" + rec.Channel,
		ReadAt: rec.ReadAt,
		Raw:    rec.Raw,
	}
	if limit := a.opts.MaxEventBytes; limit > 0 && len(ev.Raw) > limit {
		ev.Raw, ev.Truncated, ev.OriginalSize = truncateUTF8(ev.Raw, limit), true, len(rec.Raw)
		a.truncated.Add(1)
		a.log.Warn("zdarzenie przekracza limit rozmiaru – przycięte", "channel", rec.Channel,
			"record", rec.RecordID, "size", len(rec.Raw), "limit", limit)
	}
	size := len(ev.Raw) + eventOverhead
	if len(b.pending) > 0 && b.bytes+size > a.opts.MaxBytes {
		if err := b.flush(ctx); err != nil {
			return err
		}
	}
	ev.ID = contract.EventID(a.opts.AgentID, rec.Channel, cs.Generation, rec.RecordID)
	b.pending = append(b.pending, ev)
	b.bytes += size
	b.markAdvance(rec.Channel, cs)

	if len(b.pending) >= a.opts.MaxEvents {
		return b.flush(ctx)
	}
	return nil
}

func (b *batcher) markAdvance(channel string, cs state.ChannelState) {
	if b.advance == nil {
		b.advance = map[string]state.ChannelState{}
	}
	b.advance[channel] = cs
}

// flush wysyła paczkę (jeśli niepusta) i po potwierdzeniu zapisuje pozycje.
// Pozycje samych odfiltrowanych zdarzeń też są zapisywane, żeby po restarcie
// nie czytać ich ponownie.
func (b *batcher) flush(ctx context.Context) error {
	if len(b.pending) == 0 && len(b.advance) == 0 {
		return nil
	}
	a := b.agent
	if len(b.pending) > 0 {
		batch := &contract.Batch{
			Schema:  contract.SchemaBatchV1,
			BatchID: contract.NewBatchID(),
			AgentID: a.opts.AgentID,
			SentAt:  time.Now().UTC(),
			Events:  b.pending,
		}
		if err := a.sender.Send(ctx, batch); err != nil {
			return err
		}
		a.sent.Add(int64(len(b.pending)))
	}

	maps.Copy(b.st.Channels, b.advance)
	if err := a.store.Save(b.st); err != nil {
		// Paczka jest już na serwerze; brak zapisu oznacza tylko ponowną
		// wysyłkę po restarcie (duplikaty, nie luki).
		a.log.Error("nie udało się zapisać stanu", "err", err)
	}
	b.pending = nil
	b.bytes = 0
	b.advance = nil
	return nil
}

// truncateUTF8 przycina tekst do limit bajtów, nie rozcinając znaku UTF-8.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
