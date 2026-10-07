package urd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// fill buduje archiwum: 3 godziny po 2 segmenty z 3 paczkami, potem
// pusta godzina, i zamyka godziny manifestami.
func fill(t *testing.T) (*Archive, *MemCatalog, *clock) {
	t.Helper()
	ctx := context.Background()
	cat := NewMemCatalog()
	clk := &clock{t: time.Date(2026, 10, 7, 10, 5, 0, 0, time.UTC)}
	a := New(t.TempDir(), cat)
	a.Now = clk.now
	for h := range 3 {
		for s := range 2 {
			w, err := a.OpenSegment()
			if err != nil {
				t.Fatal(err)
			}
			for r := range 3 {
				payload := []byte(strings.Repeat(fmt.Sprintf("paczka %d/%d/%d ", h, s, r), 50))
				if err := w.Add(RecordMeta{Agent: "agt-1", Batch: fmt.Sprintf("b%d%d%d", h, s, r), ReceivedAt: clk.t}, payload); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			clk.t = clk.t.Add(10 * time.Minute)
		}
		clk.t = clk.t.Add(time.Hour - 20*time.Minute)
	}
	clk.t = clk.t.Add(time.Hour) // pusta godzina 13:00
	n, err := a.Seal(ctx)
	if err != nil || n != 4 {
		t.Fatalf("seal: %d %v", n, err)
	}
	return a, cat, clk
}

func mustOK(t *testing.T, a *Archive) Verification {
	t.Helper()
	v := a.Verify(context.Background(), VerifyOptions{})
	if !v.OK {
		t.Fatalf("weryfikacja powinna przejść: %v", v.Problems)
	}
	return v
}

func mustFail(t *testing.T, a *Archive, want string) {
	t.Helper()
	v := a.Verify(context.Background(), VerifyOptions{})
	if v.OK {
		t.Fatalf("weryfikacja powinna wykryć: %s", want)
	}
	for _, p := range v.Problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("brak problemu %q w %v", want, v.Problems)
}

func TestArchiveRoundtrip(t *testing.T) {
	a, cat, _ := fill(t)
	v := mustOK(t, a)
	if v.Manifests != 4 || v.Segments != 6 || v.Records != 18 {
		t.Fatalf("liczniki: %+v", v)
	}
	ms, _ := cat.Manifests(context.Background())
	if ms[0].PrevSHA256 != GenesisPrev || ms[1].PrevSHA256 != ms[0].SHA256 || ms[3].Segments != 0 {
		t.Fatalf("łańcuch: %+v", ms)
	}

	// Rekordy da się odczytać z powrotem.
	f, err := os.Open(filepath.Join(a.Dir, filepath.FromSlash(SegmentPath(ms[0].Hour, ms[0].Hour.Add(5*time.Minute)))))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	meta, payload, err := r.Next()
	if err != nil || meta.Batch != "b000" || !bytes.HasPrefix(payload, []byte("paczka 0/0/0")) || meta.SHA256 != SumHex(payload) {
		t.Fatalf("rekord: %+v %v", meta, err)
	}
	for range 2 {
		if _, _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.Next(); err != io.EOF {
		t.Fatalf("koniec segmentu: %v", err)
	}

	// Kolejne Seal w tej samej godzinie nic nie dodaje.
	if n, err := a.Seal(context.Background()); n != 0 || err != nil {
		t.Fatalf("ponowny seal: %d %v", n, err)
	}
}

func segFiles(t *testing.T, a *Archive) []string {
	t.Helper()
	files, err := a.listFiles()
	if err != nil {
		t.Fatal(err)
	}
	var segs []string
	for _, f := range files {
		if strings.HasPrefix(f, "segments/") {
			segs = append(segs, filepath.Join(a.Dir, filepath.FromSlash(f)))
		}
	}
	if len(segs) == 0 {
		t.Fatal("brak segmentów")
	}
	return segs
}

func rewrite(t *testing.T, path string, change func([]byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o640)
	if err := os.WriteFile(path, change(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetection(t *testing.T) {
	t.Run("zmieniony bajt treści", func(t *testing.T) {
		a, _, _ := fill(t)
		rewrite(t, segFiles(t, a)[0], func(b []byte) []byte { b[len(b)-10] ^= 1; return b })
		mustFail(t, a, "SHA-256 pliku nie zgadza się")
		mustFail(t, a, "niezgodnych z ich sumą")
	})
	t.Run("usunięty segment", func(t *testing.T) {
		a, _, _ := fill(t)
		removeFile(segFiles(t, a)[2])
		mustFail(t, a, "brak pliku – usunięty")
	})
	t.Run("ucięty segment", func(t *testing.T) {
		a, _, _ := fill(t)
		rewrite(t, segFiles(t, a)[1], func(b []byte) []byte { return b[:len(b)-5] })
		mustFail(t, a, "ucięty")
	})
	t.Run("dodany plik", func(t *testing.T) {
		a, _, _ := fill(t)
		extra := filepath.Join(a.Dir, "segments", "2026", "10", "07", "10", "seg-1.urd")
		if err := os.WriteFile(extra, []byte(Magic), 0o640); err != nil {
			t.Fatal(err)
		}
		mustFail(t, a, "nie występuje w spisie")
	})
	t.Run("podmieniony manifest na dysku", func(t *testing.T) {
		a, _, _ := fill(t)
		rewrite(t, filepath.Join(a.Dir, filepath.FromSlash(ManifestPath(time.Date(2026, 10, 7, 11, 0, 0, 0, time.UTC)))),
			func(b []byte) []byte { return bytes.Replace(b, []byte(`"records": 6`), []byte(`"records": 5`), 1) })
		mustFail(t, a, "różni się od zapisu w bazie")
	})
	t.Run("manifest usunięty z bazy", func(t *testing.T) {
		a, cat, _ := fill(t)
		cat.DeleteManifestRow(2)
		mustFail(t, a, "luka w łańcuchu")
		mustFail(t, a, "łańcuch przerwany")
		mustFail(t, a, "nie występuje w spisie")
	})
	t.Run("usunięty koniec łańcucha", func(t *testing.T) {
		a, cat, clk := fill(t)
		cat.DeleteManifestRow(4)
		cat.DeleteManifestRow(3)
		removeFile(filepath.Join(a.Dir, filepath.FromSlash(ManifestPath(time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)))))
		removeFile(filepath.Join(a.Dir, filepath.FromSlash(ManifestPath(time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC)))))
		for _, f := range segFiles(t, a)[4:] {
			removeFile(f)
		}
		clk.t = clk.t.Add(2 * time.Hour)
		mustFail(t, a, "koniec łańcucha usunięto")
	})
	t.Run("zmieniona treść manifestu w bazie", func(t *testing.T) {
		a, cat, _ := fill(t)
		cat.manifests[0].Body = bytes.Replace(cat.manifests[0].Body, []byte(`"records": 6`), []byte(`"records": 7`), 1)
		mustFail(t, a, "treść w bazie nie zgadza się z hashem")
	})
}

func TestExpireKeepsChain(t *testing.T) {
	a, cat, clk := fill(t)
	ctx := context.Background()
	clk.t = time.Date(2026, 10, 7, 13, 30, 0, 0, time.UTC)
	// Retencja 2 h: wygasają godziny 10:00 i 11:00 (koniec ≤ 11:30).
	n, err := a.Expire(ctx, 2*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	clk.t = clk.t.Add(time.Hour)
	if n, err = a.Expire(ctx, 2*time.Hour); err != nil || n != 1 {
		t.Fatalf("expire 2: %d %v", n, err)
	}
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	v := mustOK(t, a)
	if v.Manifests != 2 || v.Segments != 2 {
		t.Fatalf("po retencji: %+v", v)
	}
	if _, err := os.Stat(filepath.Join(a.Dir, "segments", "2026", "10", "07", "10")); !os.IsNotExist(err) {
		t.Fatalf("katalog wygasłej godziny powinien zniknąć: %v", err)
	}
	if ms, _ := cat.Manifests(ctx); len(ms) != 4 || ms[0].ExpiredAt == nil {
		t.Fatalf("wpisy wygasłe zostają: %d", len(ms))
	}
}

func TestOpenSegmentAndCleanTemp(t *testing.T) {
	a, cat, _ := fill(t)
	w, err := a.OpenSegment()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Add(RecordMeta{Agent: "a", ReceivedAt: time.Now()}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	// Otwarty (.tmp) segment nie psuje weryfikacji.
	mustOK(t, a)
	w.f.Close()
	if n, err := a.CleanTemp(); err != nil || n != 1 {
		t.Fatalf("clean: %d %v", n, err)
	}
	// Segment zatwierdzony po zamknięciu godziny trafia do kolejnego manifestu.
	w, _ = a.OpenSegment()
	_ = w.Add(RecordMeta{Agent: "a", ReceivedAt: time.Now()}, []byte("y"))
	if _, err := w.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.Now = func() time.Time { return time.Date(2026, 10, 7, 15, 1, 0, 0, time.UTC) }
	if n, err := a.Seal(context.Background()); err != nil || n != 1 {
		t.Fatalf("seal: %d %v", n, err)
	}
	if open, _ := cat.OpenSegments(context.Background()); len(open) != 0 {
		t.Fatalf("segment powinien być w manifeście: %+v", open)
	}
	mustOK(t, a)
}

func TestRollingVerificationBudget(t *testing.T) {
	a, _, _ := fill(t) // manifesty 1–3 z danymi, 4 pusty
	ctx := context.Background()
	small := VerifyOptions{BudgetBytes: 1} // jeden manifest z danymi na przebieg

	v := a.Verify(ctx, small)
	if !v.OK || v.FullManifests != 1 || v.Unverified != 3 || v.OldestFullCheck != nil || v.Segments != 6 {
		t.Fatalf("przebieg 1: %+v", v)
	}
	// Zmiana treści bez zmiany rozmiaru w segmencie godziny 12:00 (manifest 3).
	segs := segFiles(t, a)
	rewrite(t, segs[len(segs)-1], func(b []byte) []byte { b[len(b)-3] ^= 1; return b })

	if v := a.Verify(ctx, small); !v.OK || v.FullManifests != 1 {
		t.Fatalf("przebieg 2 (manifest 2) nie czyta jeszcze zmienionego segmentu: %+v", v)
	}
	if v := a.Verify(ctx, small); v.OK {
		t.Fatal("przebieg 3 powinien wykryć zmianę w manifeście 3")
	}
	// Manifest z problemem nie dostaje znacznika – wraca w kolejnym przebiegu.
	if v := a.Verify(ctx, small); v.OK {
		t.Fatal("niezgodność nie może zniknąć z widoku w następnym przebiegu")
	}
	// Usunięcie pliku wykrywa każdy przebieg (sprawdzenie obecności i rozmiaru).
	removeFile(segs[0])
	if v := a.Verify(ctx, small); v.OK {
		t.Fatal("usunięty segment powinien zostać wykryty od razu")
	}
}

func TestFullVerificationCoverage(t *testing.T) {
	a, _, _ := fill(t)
	v := a.Verify(context.Background(), VerifyOptions{})
	if !v.OK || v.FullManifests != 4 || v.Unverified != 0 || v.OldestFullCheck == nil || v.Records != 18 {
		t.Fatalf("pełne sprawdzenie: %+v", v)
	}
}
