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

	"siem/internal/agent/source"
	"siem/internal/agent/state"
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
}

// Agent to rdzeń agenta.
type Agent struct {
	opts    Options
	sources []source.Source
	sender  Sender
	store   StateStore
	log     *slog.Logger

	read, filtered, sent atomic.Int64
}

// New tworzy agenta.
func New(opts Options, sources []source.Source, sender Sender, store StateStore, log *slog.Logger) *Agent {
	if opts.RetryDelay == nil {
		opts.RetryDelay = func(error) time.Duration { return 10 * time.Second }
	}
	if opts.StatsEvery == 0 {
		opts.StatsEvery = time.Minute
	}
	return &Agent{opts: opts, sources: sources, sender: sender, store: store, log: log}
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
			a.logStats()
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
			a.logStats()
		}
	}
}

func (a *Agent) runSource(ctx context.Context, src source.Source, start source.Position, out chan<- source.Record) {
	pos := start
	for {
		var err error
		pos, err = src.Run(ctx, pos, out)
		if ctx.Err() != nil {
			return
		}
		delay := a.opts.RetryDelay(err)
		a.log.Warn("źródło zatrzymane, ponowię", "channel", src.Channel(), "err", err, "retry_in", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) logStats() {
	a.log.Info("statystyki", "read", a.read.Load(), "filtered", a.filtered.Load(), "sent_accepted", a.sent.Load())
}

// batcher zbiera zdarzenia w paczkę. Działa w jednej gorutynie.
type batcher struct {
	agent    *Agent
	st       state.State                   // potwierdzony stan (to, co na dysku)
	lastSeen map[string]state.ChannelState // ostatni odczytany rekord (wykrywanie resetu numeracji)
	pending  []contract.Event
	bytes    int
	advance  map[string]state.ChannelState // pozycje do zapisania po potwierdzeniu
}

func (b *batcher) add(ctx context.Context, rec source.Record) error {
	a := b.agent
	a.read.Add(1)

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

	size := len(rec.Raw) + eventOverhead
	if len(b.pending) > 0 && b.bytes+size > a.opts.MaxBytes {
		if err := b.flush(ctx); err != nil {
			return err
		}
	}
	b.pending = append(b.pending, contract.Event{
		ID:     contract.EventID(a.opts.AgentID, rec.Channel, cs.Generation, rec.RecordID),
		Source: "wineventlog:" + rec.Channel,
		ReadAt: rec.ReadAt,
		Raw:    rec.Raw,
	})
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

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
