package archiver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"siem/internal/urd"
	"siem/server/internal/bus"
	"siem/server/internal/metrics"
)

var testMetrics = metrics.NewArchiver()

type fakeMsg struct {
	data       []byte
	hdr        nats.Header
	seq        uint64
	acked, nak bool
}

func (m *fakeMsg) Data() []byte         { return m.data }
func (m *fakeMsg) Headers() nats.Header { return m.hdr }
func (m *fakeMsg) Subject() string      { return "siem.raw." + m.hdr.Get(bus.HdrAgent) }
func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: m.seq}}, nil
}
func (m *fakeMsg) Ack() error                       { m.acked = true; return nil }
func (m *fakeMsg) NakWithDelay(time.Duration) error { m.nak = true; return nil }

func newMsg(seq uint64, at time.Time) *fakeMsg {
	h := nats.Header{}
	h.Set(bus.HdrAgent, "agt-1")
	h.Set(bus.HdrBatch, "batch-"+string(rune('a'+seq%26)))
	h.Set(bus.HdrEncoding, "gzip")
	h.Set(bus.HdrReceivedAt, at.Format(time.RFC3339Nano))
	return &fakeMsg{data: []byte("skompresowana paczka"), hdr: h, seq: seq}
}

func TestArchiverAcksAfterCommitAndSeals(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 59, 0, 0, time.UTC)
	cat := urd.NewMemCatalog()
	a := urd.New(t.TempDir(), cat)
	a.Now = func() time.Time { return now }
	r := &Archiver{A: a, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), M: testMetrics,
		Cfg: Config{SegmentMaxBytes: 1 << 20, SegmentMaxAge: 30 * time.Second}}

	var msgs []*fakeMsg
	for i := range 5 {
		m := newMsg(uint64(i+1), now)
		msgs = append(msgs, m)
		if err := r.Add(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.acked {
			t.Fatal("potwierdzenie przed zapisem segmentu")
		}
	}
	now = now.Add(31 * time.Second)
	if err := r.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if !m.acked || m.nak {
			t.Fatalf("wiadomość powinna być potwierdzona: %+v", m)
		}
	}

	// Nowa godzina: segment z poprzedniej jest zamykany, a godzina dostaje manifest.
	m := newMsg(6, now)
	_ = r.Add(ctx, m)
	now = time.Date(2026, 10, 7, 11, 0, 5, 0, time.UTC)
	if err := r.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if !m.acked {
		t.Fatal("segment z poprzedniej godziny powinien zostać zatwierdzony")
	}
	last, ok, _ := cat.LastManifest(ctx)
	if !ok || !last.Hour.Equal(time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)) || last.Segments != 2 || last.Records != 6 {
		t.Fatalf("manifest: %+v", last)
	}
	if v := a.Verify(ctx, urd.VerifyOptions{}); !v.OK || v.Records != 6 || v.FinishedAt.IsZero() {
		t.Fatalf("weryfikacja: %+v", v)
	}
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestArchiverNaksOnCommitFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cat := &failingCatalog{MemCatalog: urd.NewMemCatalog()}
	a := urd.New(dir, cat)
	r := &Archiver{A: a, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), M: testMetrics,
		Cfg: Config{SegmentMaxBytes: 1, SegmentMaxAge: time.Hour}}
	m := newMsg(1, time.Now())
	if err := r.Add(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := r.Tick(ctx); err == nil {
		t.Fatal("oczekiwano błędu zatwierdzenia")
	}
	if m.acked || !m.nak {
		t.Fatalf("wiadomość powinna wrócić do kolejki: %+v", m)
	}
	// Plik nieudanego segmentu nie zostaje na dysku.
	var files int
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			files++
		}
		return nil
	})
	if files != 0 {
		t.Fatalf("pozostało %d plików", files)
	}
}

type failingCatalog struct{ *urd.MemCatalog }

func (failingCatalog) AddSegment(context.Context, urd.Segment) error {
	return errors.New("baza niedostępna")
}

func TestArchiverExcludedAgents(t *testing.T) {
	cat := urd.NewMemCatalog()
	r := &Archiver{A: urd.New(t.TempDir(), cat), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), M: testMetrics,
		Cfg: Config{SegmentMaxBytes: 1 << 20, SegmentMaxAge: time.Hour, ExcludeAgents: []string{"agt-load-"}}}
	load := newMsg(1, time.Now())
	load.hdr.Set(bus.HdrAgent, "agt-load-00042")
	real := newMsg(2, time.Now())
	for _, m := range []*fakeMsg{load, real} {
		if err := r.Add(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	if !load.acked || real.acked || r.cur == nil || r.cur.Records() != 1 {
		t.Fatalf("paczka testowa ma być potwierdzona bez zapisu: load=%v real=%v rekordy=%d", load.acked, real.acked, r.cur.Records())
	}
	r.cur.Abort()
}

func TestArchiverPausesOnLowDisk(t *testing.T) {
	free := uint64(1 << 30) // 1 GB z 100 GB
	diskUsageFn = func(string) (uint64, uint64, error) { return free, 100 << 30, nil }
	defer func() { diskUsageFn = diskUsage }()
	h := &Health{}
	r := &Archiver{A: urd.New(t.TempDir(), urd.NewMemCatalog()), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		M: testMetrics, Health: h, Cfg: Config{MinFreeBytes: 2 << 30, MinFreePercent: 5, WarnFreePercent: 15}}
	if reason := r.CheckDisk(); reason == "" {
		t.Fatal("przy 1 GB wolnego archiwizacja powinna zostać wstrzymana")
	}
	if f, tot, p := h.Get(); f != free || tot != 100<<30 || p == "" {
		t.Fatalf("stan dla panelu: %d %d %q", f, tot, p)
	}
	free = 50 << 30
	r.diskCheck = time.Time{}
	if reason := r.CheckDisk(); reason != "" {
		t.Fatalf("po zwolnieniu miejsca archiwizacja powinna ruszyć: %s", reason)
	}
	if _, _, p := h.Get(); p != "" {
		t.Fatalf("panel nadal widzi wstrzymanie: %q", p)
	}
}

type fakeExports struct {
	jobs     []urd.ExportJob
	finished []urd.ExportJob
	expired  []string
}

func (f *fakeExports) ClaimExport(context.Context) (urd.ExportJob, bool, error) {
	if len(f.jobs) == 0 {
		return urd.ExportJob{}, false, nil
	}
	j := f.jobs[0]
	f.jobs = f.jobs[1:]
	return j, true, nil
}
func (f *fakeExports) FinishExport(_ context.Context, j urd.ExportJob) error {
	f.finished = append(f.finished, j)
	return nil
}
func (f *fakeExports) FailInterruptedExports(context.Context) (int64, error) { return 0, nil }
func (f *fakeExports) ExpireExports(context.Context, time.Time) ([]string, error) {
	return f.expired, nil
}

func TestExporterWritesVerifiablePackage(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 10, 0, 0, time.UTC)
	cat := urd.NewMemCatalog()
	a := urd.New(t.TempDir(), cat)
	a.Now = func() time.Time { return now }
	w, _ := a.OpenSegment()
	_ = w.Add(urd.RecordMeta{Agent: "agt-1", Batch: "b1", ReceivedAt: now}, []byte("paczka"))
	if _, err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	store := &fakeExports{jobs: []urd.ExportJob{
		{ID: 1, RequestedBy: "adam", Reason: "audyt", From: from, To: from.Add(time.Hour)},
		{ID: 2, RequestedBy: "adam", Reason: "pusty zakres", From: from.Add(-48 * time.Hour), To: from.Add(-47 * time.Hour)},
	}}
	e := &Exporter{A: a, Store: store, Dir: dir, Keep: time.Hour, Version: "test",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Lock: &sync.Mutex{}}
	for {
		j, ok, _ := store.ClaimExport(ctx)
		if !ok {
			break
		}
		_ = store.FinishExport(ctx, e.runJob(ctx, j))
	}
	ok, bad := store.finished[0], store.finished[1]
	if ok.Status != urd.ExportDone || ok.Records != 1 || len(ok.SHA256) != 64 || !urd.ValidExportName(ok.FileName) {
		t.Fatalf("eksport: %+v", ok)
	}
	if bad.Status != urd.ExportFailed || bad.Error == "" {
		t.Fatalf("pusty zakres powinien się nie udać: %+v", bad)
	}
	f, err := os.Open(filepath.Join(dir, ok.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if c := urd.CheckExport(f); !c.OK || c.Records != 1 {
		t.Fatalf("paczka z dysku: %+v", c)
	}
	// Wygasła paczka jest usuwana.
	store.expired = []string{ok.FileName}
	f.Close()
	e.expire(ctx)
	if _, err := os.Stat(filepath.Join(dir, ok.FileName)); !os.IsNotExist(err) {
		t.Fatalf("paczka powinna zniknąć: %v", err)
	}
}

type fakeReplays struct {
	jobs     []urd.ReplayJob
	finished []urd.ReplayJob
}

func (f *fakeReplays) ClaimReplay(context.Context) (urd.ReplayJob, bool, error) {
	if len(f.jobs) == 0 {
		return urd.ReplayJob{}, false, nil
	}
	j := f.jobs[0]
	f.jobs = f.jobs[1:]
	return j, true, nil
}
func (f *fakeReplays) ReplayProgress(context.Context, int64, urd.ReplayStats) error { return nil }
func (f *fakeReplays) FinishReplay(_ context.Context, j urd.ReplayJob) error {
	f.finished = append(f.finished, j)
	return nil
}
func (f *fakeReplays) FailInterruptedReplays(context.Context) (int64, error) { return 0, nil }

type fakePub struct {
	msgs     []*nats.Msg
	ids      []string
	fullOnce bool
}

func (p *fakePub) PublishMsg(_ context.Context, m *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if p.fullOnce {
		p.fullOnce = false
		return nil, &jetstream.APIError{ErrorCode: 10077, Description: "maximum bytes exceeded"}
	}
	p.msgs = append(p.msgs, m)
	return &jetstream.PubAck{}, nil
}

func TestReplayerPublishesToReplayPipeline(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 10, 0, 0, time.UTC)
	a := urd.New(t.TempDir(), urd.NewMemCatalog())
	a.Now = func() time.Time { return now }
	w, _ := a.OpenSegment()
	for _, agent := range []string{"agt-1", "agt-2", "agt-1"} {
		_ = w.Add(urd.RecordMeta{Agent: agent, Batch: "b-" + agent, Encoding: "gzip", ReceivedAt: now}, []byte("paczka "+agent))
	}
	if _, err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}

	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	store := &fakeReplays{}
	pub := &fakePub{fullOnce: true}
	r := &Replayer{A: a, Store: store, Pub: pub, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Lock: &sync.Mutex{},
		RetryWait: time.Millisecond}
	j := r.runJob(ctx, urd.ReplayJob{ID: 5, From: from, To: from.Add(time.Hour), Agents: []string{"agt-1"}})
	if j.Status != urd.ReplayDone || j.Batches != 2 || j.Skipped != 1 {
		t.Fatalf("odtworzenie: %+v", j)
	}
	if len(pub.msgs) != 2 {
		t.Fatalf("pełny strumień powinien zostać ponowiony: %d wiadomości", len(pub.msgs))
	}
	m := pub.msgs[0]
	if m.Subject != "siem.replay.raw.agt-1" || m.Header.Get(bus.HdrReplay) != "5" || m.Header.Get(bus.HdrAgent) != "agt-1" ||
		m.Header.Get(bus.HdrReceivedAt) == "" || string(m.Data) != "paczka agt-1" {
		t.Fatalf("wiadomość: %s %v %q", m.Subject, m.Header, m.Data)
	}
	// Pusty zakres: zlecenie nieudane z opisem.
	if j := r.runJob(ctx, urd.ReplayJob{ID: 6, From: from.Add(-48 * time.Hour), To: from.Add(-47 * time.Hour)}); j.Status != urd.ReplayFailed || j.Error == "" {
		t.Fatalf("pusty zakres: %+v", j)
	}
}

func TestArchiverPolicy(t *testing.T) {
	pol := NewPolicy(urd.Policy{Enabled: true, RetentionDays: 10, ExcludedAgents: []string{"agt-x"}, ExcludedGroups: []int64{7}},
		urd.PolicyBounds{MinRetentionDays: 30, MaxRetentionDays: 365})
	r := &Archiver{Cfg: Config{ExcludeAgents: []string{"agt-load-"}}, Policy: pol}
	// Przypisania grup jeszcze nieznane – wykluczenie grupy nie działa (archiwum zbiera wszystko).
	if got := r.skipReason("agt-in-7"); got != "" {
		t.Fatalf("grupy nieznane: %q", got)
	}
	pol.Set(pol.Current(), map[string]int64{"agt-in-7": 7, "agt-in-2": 2}, 7, true)
	for agent, want := range map[string]string{
		"agt-load-1": skipPrefix, "agt-x": skipAgent, "agt-in-7": skipGroup, "agt-in-2": "",
		"agt-nowy": skipGroup, // bez przypisania – grupa domyślna (7)
	} {
		if got := r.skipReason(agent); got != want {
			t.Errorf("%s: %q, oczekiwano %q", agent, got, want)
		}
	}
	// Retencja nigdy poniżej minimum z konfiguracji serwera.
	if got := pol.Retention(); got != 30*24*time.Hour {
		t.Fatalf("retencja: %v", got)
	}
	pol.Set(urd.Policy{Enabled: false, RetentionDays: 90}, nil, 0, false)
	if got := r.skipReason("agt-in-2"); got != skipDisabled || pol.Retention() != 90*24*time.Hour {
		t.Fatalf("wyłączone archiwum: %q %v", got, pol.Retention())
	}
}
