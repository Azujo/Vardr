package archiver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	if v := a.Verify(ctx); !v.OK || v.Records != 6 || v.FinishedAt.IsZero() {
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
