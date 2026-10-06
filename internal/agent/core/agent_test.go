package core

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"siem/internal/agent/source"
	"siem/internal/agent/state"
	"siem/internal/agent/status"
	"siem/internal/contract"
)

type fakeSource struct {
	channel string
	records []source.Record
	gotPos  chan source.Position
}

func (f *fakeSource) Channel() string { return f.channel }

func (f *fakeSource) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	f.gotPos <- start
	pos := start
	for _, r := range f.records {
		select {
		case out <- r:
			pos = source.Position{RecordID: r.RecordID, Valid: true}
		case <-ctx.Done():
			return pos, ctx.Err()
		}
	}
	<-ctx.Done()
	return pos, ctx.Err()
}

type fakeSender struct {
	mu      sync.Mutex
	batches []*contract.Batch
	block   bool
}

func (f *fakeSender) Send(ctx context.Context, b *contract.Batch) error {
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, b)
	return nil
}

func (f *fakeSender) events() []contract.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []contract.Event
	for _, b := range f.batches {
		out = append(out, b.Events...)
	}
	return out
}

type memStore struct {
	mu      sync.Mutex
	st      state.State
	origin  state.Origin
	missing bool
	saves   int
}

func (m *memStore) Load() (state.State, state.Origin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := state.State{Channels: map[string]state.ChannelState{}}
	for k, v := range m.st.Channels {
		st.Channels[k] = v
	}
	origin := m.origin
	if origin == state.OriginFresh && len(st.Channels) > 0 {
		origin = state.OriginFile
	}
	return st, origin, nil
}

func (m *memStore) Missing() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.missing
}

func (m *memStore) setMissing() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.missing = true
}

func (m *memStore) saveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saves
}

func (m *memStore) Save(st state.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	m.missing = false
	m.st = state.State{Channels: map[string]state.ChannelState{}}
	for k, v := range st.Channels {
		m.st.Channels[k] = v
	}
	return nil
}

func (m *memStore) get(ch string) state.ChannelState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Channels[ch]
}

func recs(channel string, ids ...uint64) []source.Record {
	var out []source.Record
	for _, id := range ids {
		out = append(out, source.Record{Channel: channel, RecordID: id, EventID: 7036, HasEventID: true, Raw: "<Event/>"})
	}
	return out
}

func run(t *testing.T, opts Options, src *fakeSource, snd *fakeSender, store *memStore, until func() bool) {
	t.Helper()
	if opts.AgentID == "" {
		opts.AgentID = "agt-t"
	}
	if opts.MaxEvents == 0 {
		opts.MaxEvents = 100
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 1 << 20
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 10 * time.Millisecond
	}
	a := New(opts, []source.Source{src}, snd, store, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !until() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("przekroczono czas oczekiwania")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSendsAndSavesPositionAfterAck(t *testing.T) {
	src := &fakeSource{channel: "System", records: recs("System", 1, 2, 3, 4, 5), gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}

	run(t, Options{}, src, snd, store, func() bool { return store.get("System").RecordID == 5 })

	ev := snd.events()
	if len(ev) != 5 || ev[0].ID != "agt-t:System:g0:1" || ev[0].Source != "wineventlog:System" {
		t.Fatalf("zdarzenia: %+v", ev)
	}
}

func TestNoAckNoPositionSaved(t *testing.T) {
	src := &fakeSource{channel: "System", records: recs("System", 1, 2, 3), gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{block: true}
	store := &memStore{}

	start := time.Now()
	run(t, Options{}, src, snd, store, func() bool { return time.Since(start) > 100*time.Millisecond })

	if got := store.get("System"); got.RecordID != 0 {
		t.Fatalf("pozycja zapisana bez potwierdzenia serwera: %+v", got)
	}
}

func TestResumesFromSavedPosition(t *testing.T) {
	src := &fakeSource{channel: "System", gotPos: make(chan source.Position, 1)}
	store := &memStore{st: state.State{Channels: map[string]state.ChannelState{"System": {RecordID: 41}}}}

	var pos source.Position
	run(t, Options{}, src, &fakeSender{}, store, func() bool {
		select {
		case pos = <-src.gotPos:
			return true
		default:
			return false
		}
	})
	if pos != (source.Position{RecordID: 41, Valid: true}) {
		t.Fatalf("źródło uruchomione od %+v", pos)
	}
}

func TestGenerationBumpsOnRecordReset(t *testing.T) {
	src := &fakeSource{channel: "System", records: recs("System", 10, 11, 3), gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}

	run(t, Options{}, src, snd, store, func() bool { return len(snd.events()) == 3 })

	ev := snd.events()
	if ev[1].ID != "agt-t:System:g0:11" || ev[2].ID != "agt-t:System:g1:3" {
		t.Fatalf("identyfikatory: %s, %s", ev[1].ID, ev[2].ID)
	}
}

func TestAgentSideFilterAdvancesPosition(t *testing.T) {
	r := recs("Security", 1, 2, 3)
	r[1].EventID = 5156 // szum – poza listą
	src := &fakeSource{channel: "Security", records: r, gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}
	opts := Options{Filters: map[string]map[uint32]bool{"Security": {7036: true}}}

	run(t, opts, src, snd, store, func() bool { return store.get("Security").RecordID == 3 })

	if ev := snd.events(); len(ev) != 2 {
		t.Fatalf("oczekiwano 2 zdarzeń po filtrze, jest %d", len(ev))
	}
}

func TestSplitsByMaxEvents(t *testing.T) {
	src := &fakeSource{channel: "System", records: recs("System", 1, 2, 3, 4, 5, 6, 7), gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}

	run(t, Options{MaxEvents: 3}, src, snd, store, func() bool { return store.get("System").RecordID == 7 })

	snd.mu.Lock()
	defer snd.mu.Unlock()
	for _, b := range snd.batches {
		if len(b.Events) > 3 {
			t.Fatalf("paczka przekracza max_events: %d", len(b.Events))
		}
	}
}

func TestMaxEPSThrottlesWithoutLoss(t *testing.T) {
	ids := make([]uint64, 60)
	for i := range ids {
		ids[i] = uint64(i + 1)
	}
	src := &fakeSource{channel: "System", records: recs("System", ids...), gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}

	start := time.Now()
	// 60 zdarzeń przy limicie 40/s i zapasie 40 => ok. 0,5 s.
	run(t, Options{MaxEPS: 40}, src, snd, store, func() bool { return store.get("System").RecordID == 60 })
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Fatalf("limit EPS nie zadziałał: 60 zdarzeń w %v", el)
	}
	if len(snd.events()) != 60 {
		t.Fatalf("limit nie może gubić zdarzeń: %d", len(snd.events()))
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}

func TestWarnsWhenLagExceedsThreshold(t *testing.T) {
	r := recs("System", 1, 2)
	for i := range r {
		r[i].ReadAt = time.Now()
		r[i].CreatedAt = r[i].ReadAt.Add(-10 * time.Minute) // zdarzenie sprzed 10 min
	}
	src := &fakeSource{channel: "System", records: r, gotPos: make(chan source.Position, 1)}
	var logBuf syncBuffer
	a := New(Options{AgentID: "agt-t", MaxEvents: 10, MaxBytes: 1 << 20, FlushInterval: 5 * time.Millisecond,
		StatsEvery: 20 * time.Millisecond, LagWarn: 5 * time.Minute},
		[]source.Source{src}, &fakeSender{}, &memStore{}, slog.New(slog.NewTextHandler(&logBuf, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)
	if out := logBuf.String(); !strings.Contains(out, "nie nadąża") || !strings.Contains(out, "lag_max=10m") {
		t.Fatalf("brak ostrzeżenia o opóźnieniu w logu:\n%s", out)
	}
}

func TestTruncatesOversizedEventsAndReportsStatus(t *testing.T) {
	r := recs("System", 1, 2)
	r[1].Raw = strings.Repeat("ż", 3000) // 6000 B, znaki dwubajtowe
	src := &fakeSource{channel: "System", records: r, gotPos: make(chan source.Position, 1)}
	snd := &fakeSender{}
	store := &memStore{}
	tr := status.NewTracker("t", "agt-t", "u", nil)

	run(t, Options{MaxEventBytes: 4097, Status: tr}, src, snd, store, func() bool { return store.get("System").RecordID == 2 })

	ev := snd.events()
	if !ev[1].Truncated || ev[1].OriginalSize != 6000 || len(ev[1].Raw) != 4096 || !utf8.ValidString(ev[1].Raw) {
		t.Fatalf("przycięcie: truncated=%v size=%d len=%d", ev[1].Truncated, ev[1].OriginalSize, len(ev[1].Raw))
	}
	if ev[0].Truncated {
		t.Fatal("małe zdarzenie nie powinno być przycięte")
	}
	s := tr.Snapshot()
	if s.Counters.Truncated != 1 || s.Counters.Read != 2 || len(s.Channels) != 1 || s.Channels[0].State != status.ChannelOK || s.Channels[0].LastRecordID != 2 {
		t.Fatalf("status: %+v", s)
	}
}

func waitPos(t *testing.T, src *fakeSource, store *memStore) source.Position {
	t.Helper()
	var pos source.Position
	run(t, Options{}, src, &fakeSender{}, store, func() bool {
		select {
		case pos = <-src.gotPos:
			return true
		default:
			return false
		}
	})
	return pos
}

func TestLostStateStartsFromOldest(t *testing.T) {
	src := &fakeSource{channel: "Security", gotPos: make(chan source.Position, 1)}
	store := &memStore{origin: state.OriginLost}

	if pos := waitPos(t, src, store); pos.Valid || !pos.Oldest {
		t.Fatalf("po utracie stanu odczyt musi zacząć się od najstarszych: %+v", pos)
	}
	if store.saveCount() == 0 {
		t.Fatal("stan po utracie powinien zostać od razu utrwalony")
	}
}

func TestBackupOriginResumesKnownChannelsAndOldestForOthers(t *testing.T) {
	store := &memStore{origin: state.OriginBackup,
		st: state.State{Channels: map[string]state.ChannelState{"Security": {RecordID: 77}}}}

	known := &fakeSource{channel: "Security", gotPos: make(chan source.Position, 1)}
	if pos := waitPos(t, known, store); pos != (source.Position{RecordID: 77, Valid: true}) {
		t.Fatalf("kanał z kopii: %+v", pos)
	}
	other := &fakeSource{channel: "System", gotPos: make(chan source.Position, 1)}
	if pos := waitPos(t, other, store); !pos.Oldest {
		t.Fatalf("kanał bez pozycji w kopii: %+v", pos)
	}
}

func TestFreshStartUsesConfiguredStart(t *testing.T) {
	src := &fakeSource{channel: "System", gotPos: make(chan source.Position, 1)}
	if pos := waitPos(t, src, &memStore{}); pos.Valid || pos.Oldest {
		t.Fatalf("pierwsze uruchomienie powinno użyć start_at z konfiguracji: %+v", pos)
	}
}

func TestDeletedStateFileIsRewrittenDuringRun(t *testing.T) {
	src := &fakeSource{channel: "System", records: recs("System", 1, 2), gotPos: make(chan source.Position, 1)}
	store := &memStore{}
	tr := status.NewTracker("t", "agt-t", "u", nil)

	deleted := false
	run(t, Options{Status: tr}, src, &fakeSender{}, store, func() bool {
		if store.get("System").RecordID == 2 && !deleted {
			store.setMissing() // „ktoś usunął state.json”
			deleted = true
		}
		return deleted && !store.Missing()
	})
	if w := tr.Snapshot().Warnings; len(w) == 0 || !strings.Contains(w[0], "usunięty w trakcie pracy") {
		t.Fatalf("brak ostrzeżenia w statusie: %q", w)
	}
	if store.get("System").RecordID != 2 {
		t.Fatal("odtworzony stan musi zawierać potwierdzone pozycje")
	}
}
