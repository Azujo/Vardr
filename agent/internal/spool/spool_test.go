// SPDX-License-Identifier: AGPL-3.0-or-later

package spool

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"siem/internal/contract"
)

// fakeNext udaje serwer: up = przyjmuje, inaczej błąd przejściowy.
type fakeNext struct {
	mu   sync.Mutex
	up   bool
	got  []string
	wake chan struct{}
}

func (f *fakeNext) isUp() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up
}

func (f *fakeNext) accept(b *contract.Batch) {
	f.mu.Lock()
	f.got = append(f.got, b.BatchID)
	f.mu.Unlock()
}

func (f *fakeNext) TrySend(_ context.Context, b *contract.Batch) (bool, error) {
	if !f.isUp() {
		return false, nil
	}
	f.accept(b)
	return true, nil
}

func (f *fakeNext) Send(ctx context.Context, b *contract.Batch) error {
	for !f.isUp() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-f.wake:
		case <-time.After(5 * time.Millisecond):
		}
	}
	f.accept(b)
	return nil
}

func batch(i int) *contract.Batch {
	return &contract.Batch{Schema: contract.SchemaBatchV1, BatchID: fmt.Sprintf("b%03d", i), AgentID: "agt-1",
		Events: []contract.Event{{ID: fmt.Sprintf("e%d", i), Source: "wineventlog:Security", Raw: "<Event/>"}}}
}

func TestSpoolBuffersWhileServerDown(t *testing.T) {
	dir := t.TempDir()
	next := &fakeNext{wake: make(chan struct{}, 1)}
	s, err := Open(dir, next, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.Configure(1<<20, OnFullPause, 0)
	ctx := context.Background()
	for i := range 5 {
		if err := s.Send(ctx, batch(i)); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.Stats(); st.Batches != 5 || st.Spooled != 5 {
		t.Fatalf("przy braku serwera paczki mają trafić do bufora: %+v", st)
	}

	// Restart agenta: bufor z dysku zostaje.
	s2, err := Open(dir, next, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s2.Configure(1<<20, OnFullPause, 0)
	if st := s2.Stats(); st.Batches != 5 {
		t.Fatalf("po restarcie: %+v", st)
	}
	// Serwer wraca: bufor dosyłany w kolejności; nowa paczka idzie za nimi.
	next.mu.Lock()
	next.up = true
	next.mu.Unlock()
	if err := s2.Send(ctx, batch(5)); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s2.Run(runCtx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for s2.Stats().Batches > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	<-done
	if len(next.got) != 6 || next.got[0] != "b000" || next.got[5] != "b005" {
		t.Fatalf("kolejność dosłania: %v", next.got)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("pliki po opróżnieniu bufora: %v", left)
	}
}

func TestSpoolFullPolicies(t *testing.T) {
	size := func() int64 {
		d, _ := encode(batch(0))
		return int64(len(d))
	}()
	// drop_oldest: limit na 3 paczki – szósta wypycha najstarsze (poza pierwszą, wysyłaną).
	next := &fakeNext{wake: make(chan struct{}, 1)}
	s, _ := Open(t.TempDir(), next, slog.New(slog.DiscardHandler))
	s.Configure(3*size+size/2, OnFullDropOldest, 0)
	for i := range 6 {
		if err := s.Send(context.Background(), batch(i)); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.Stats(); st.Batches != 3 || st.Dropped != 3 || st.DroppedTotal != 3 {
		t.Fatalf("drop_oldest: %+v", st)
	}

	// pause: przy pełnym buforze Send czeka na serwer (jak bez bufora).
	next2 := &fakeNext{wake: make(chan struct{}, 1)}
	s2, _ := Open(t.TempDir(), next2, slog.New(slog.DiscardHandler))
	s2.Configure(size+size/2, OnFullPause, 0)
	_ = s2.Send(context.Background(), batch(0))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s2.Send(ctx, batch(1)); err == nil {
		t.Fatal("pause: przy pełnym buforze i braku serwera Send ma czekać")
	}
	if st := s2.Stats(); st.Dropped != 0 || st.Batches != 1 {
		t.Fatalf("pause nie usuwa paczek: %+v", st)
	}

	// Rezerwa wolnego miejsca: bufor nie zabiera ostatnich MinFreeBytes.
	s3, _ := Open(t.TempDir(), &fakeNext{}, slog.New(slog.DiscardHandler))
	s3.FreeSpace = func(string) (uint64, error) { return 100, nil }
	s3.Configure(1<<20, OnFullDropOldest, 1000)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel3()
	if err := s3.Send(ctx3, batch(0)); err == nil || s3.Stats().Batches != 0 {
		t.Fatalf("mało miejsca na dysku – bufor nie może pisać: %+v", s3.Stats())
	}

	// Bufor wyłączony (limit 0): paczka idzie prosto do serwera.
	next4 := &fakeNext{up: true}
	s4, _ := Open(t.TempDir(), next4, slog.New(slog.DiscardHandler))
	s4.Configure(0, OnFullPause, 0)
	if err := s4.Send(context.Background(), batch(0)); err != nil || len(next4.got) != 1 || !s4.Stats().Disabled {
		t.Fatalf("bufor wyłączony: %v %v", err, next4.got)
	}
}
