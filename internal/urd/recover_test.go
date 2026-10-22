// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// snapshot kopiuje spis w pamięci (jak zrzut bazy Saga w kopii zapasowej).
func (c *MemCatalog) snapshot() *MemCatalog {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := NewMemCatalog()
	for k, v := range c.segments {
		n.segments[k] = v
	}
	for k, v := range c.segSeq {
		n.segSeq[k] = v
	}
	n.manifests = slices.Clone(c.manifests)
	n.verifs = slices.Clone(c.verifs)
	return n
}

func addSegment(t *testing.T, a *Archive, clk *clock, records int) Segment {
	t.Helper()
	w, err := a.OpenSegment()
	if err != nil {
		t.Fatal(err)
	}
	for r := range records {
		if err := w.Add(RecordMeta{Agent: "agt-1", ReceivedAt: clk.t}, []byte(strings.Repeat("x", 100+r))); err != nil {
			t.Fatal(err)
		}
	}
	s, err := w.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Przywrócenie starszej kopii spisu: manifesty i segmenty zapisane po
// zrzucie wracają do spisu (łańcuch i sumy zgodne), plik spoza okna
// zostaje zgłoszony, a po decyzji administratora trafia do kwarantanny.
func TestReconcileAfterRestore(t *testing.T) {
	ctx := context.Background()
	a, cat, clk := fill(t) // manifesty 10:00–13:00, teraz 14:05
	dumpAt := clk.t
	dump := cat.snapshot()

	// Po zrzucie: segment w 14:00, zamknięcie godziny 14, dwa segmenty w 15:00
	// (bez manifestu – archiwizator zatrzymany przed końcem godziny).
	clk.t = clk.t.Add(5 * time.Minute)
	addSegment(t, a, clk, 2)
	clk.t = time.Date(2026, 10, 7, 15, 1, 0, 0, time.UTC)
	if n, err := a.Seal(ctx); err != nil || n != 1 {
		t.Fatalf("seal 14: %d %v", n, err)
	}
	s1 := addSegment(t, a, clk, 3)
	clk.t = clk.t.Add(time.Minute)
	s2 := addSegment(t, a, clk, 1)
	restoredAt := clk.t.Add(time.Minute)

	// Plik podrzucony wcześniej (sprzed zrzutu) – nie może wejść automatycznie.
	foreign := SegmentPath(time.Date(2026, 10, 7, 11, 0, 0, 0, time.UTC), time.Date(2026, 10, 7, 11, 30, 0, 0, time.UTC))
	data, _ := os.ReadFile(a.abs(s2.Path))
	if err := os.WriteFile(a.abs(foreign), data, 0o440); err != nil {
		t.Fatal(err)
	}

	// Przywrócenie spisu z kopii.
	a.Cat = dump
	clk.t = restoredAt.Add(time.Minute)
	v := a.Verify(ctx, VerifyOptions{})
	if v.OK || len(v.Unknown) != 5 { // manifest 14, segment 14, s1, s2, obcy
		t.Fatalf("przed uzgodnieniem: %v %v", v.Unknown, v.Problems)
	}

	from, to := dumpAt.Add(-10*time.Minute), restoredAt
	res, err := a.Run(ctx, Recovery{Kind: "restore", WindowFrom: &from, WindowTo: &to})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Manifests) != 1 || res.Manifests[0].Seq != 5 || len(res.Segments) != 2 || len(res.Rejected) != 1 ||
		res.Rejected[0].Path != foreign || !strings.Contains(res.Rejected[0].Reason, "poza oknem") {
		t.Fatalf("wynik: %+v", res)
	}
	if !strings.Contains(res.Summary(), "przywrócone manifesty: 1") {
		t.Fatal(res.Summary())
	}
	// Ponowne uzgodnienie niczego nie dubluje.
	if again, err := a.Run(ctx, Recovery{Kind: "restore", WindowFrom: &from, WindowTo: &to}); err != nil ||
		len(again.Manifests)+len(again.Segments) != 0 {
		t.Fatalf("drugi przebieg: %+v %v", again, err)
	}
	// Przyjęte segmenty trafiają do manifestu 15:00 przy zamknięciu godziny.
	clk.t = time.Date(2026, 10, 7, 16, 0, 30, 0, time.UTC)
	if n, err := a.Seal(ctx); err != nil || n != 1 {
		t.Fatalf("seal 15: %d %v", n, err)
	}
	ms, _ := dump.Manifests(ctx)
	if last := ms[len(ms)-1]; last.Segments != 2 || last.Records != int64(s1.Records+s2.Records) {
		t.Fatalf("manifest 15: %+v", last)
	}
	mustFail(t, a, "nie występuje w spisie")

	// Decyzja administratora: obcy plik do kwarantanny (zachowany).
	q, err := a.Run(ctx, Recovery{Kind: "quarantine", Paths: []string{foreign, "segments/../../etc/passwd"}})
	if err != nil || len(q.Quarantined) != 1 || len(q.Rejected) != 1 {
		t.Fatalf("kwarantanna: %+v %v", q, err)
	}
	if _, err := os.Stat(a.abs(q.Quarantined[0])); err != nil {
		t.Fatalf("plik w kwarantannie: %v", err)
	}
	mustOK(t, a)
	if err := a.LogRecovery(Recovery{ID: 7, Kind: "quarantine", Result: &q}); err != nil {
		t.Fatal(err)
	}
	if fs, _ := filepath.Glob(filepath.Join(a.Dir, RecoveryLogDir, "*-quarantine-7.json")); len(fs) != 1 {
		t.Fatalf("zapis operacji: %v", fs)
	}
	mustOK(t, a) // katalog recoveries/ nie jest częścią spisu
}

// Przyjęcie przez administratora: tylko wskazane pliki, uszkodzony segment
// i manifest, który nie przedłuża łańcucha – odrzucone.
func TestReconcileAdopt(t *testing.T) {
	ctx := context.Background()
	a, cat, clk := fill(t)
	dump := cat.snapshot()
	clk.t = clk.t.Add(time.Minute)
	good := addSegment(t, a, clk, 2)
	clk.t = clk.t.Add(time.Minute)
	bad := addSegment(t, a, clk, 2)
	a.Cat = dump
	// Uszkodzenie treści „złego” segmentu.
	full := a.abs(bad.Path)
	_ = os.Chmod(full, 0o640)
	b, _ := os.ReadFile(full)
	b[len(b)-3] ^= 0xff
	if err := os.WriteFile(full, b, 0o440); err != nil {
		t.Fatal(err)
	}
	// Fałszywy manifest godziny 14 (zły hash poprzednika).
	fake := ManifestPath(time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC))
	body, _ := NewManifest(5, time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC), GenesisPrev, nil, clk.t).Encode()
	if err := writeFileAtomic(a.abs(fake), body); err != nil {
		t.Fatal(err)
	}

	res, err := a.Run(ctx, Recovery{Kind: "adopt", Paths: []string{good.Path, bad.Path, fake}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Segments) != 1 || res.Segments[0].Path != good.Path || res.Segments[0].SHA256 != good.SHA256 || len(res.Rejected) != 2 {
		t.Fatalf("przyjęcie: %+v", res)
	}
	reasons := res.Rejected[0].Reason + " | " + res.Rejected[1].Reason
	if !strings.Contains(reasons, "nie przedłuża łańcucha") || !strings.Contains(reasons, "uszkodzony") {
		t.Fatalf("powody: %s", reasons)
	}
	// Restore bez okna (nieznany czas zrzutu) – nic automatycznie.
	if _, err := a.Run(ctx, Recovery{Kind: "restore"}); err == nil {
		t.Fatal("restore bez okna powinien wymagać decyzji administratora")
	}
}

// Segment z dawnej godziny przyjęty dziś czeka na najbliższy manifest – bez
// zgłoszenia „bez manifestu od ponad godziny” (zaległość od rejestracji).
func TestReconcileOldSegmentNotStale(t *testing.T) {
	ctx := context.Background()
	a, cat, clk := fill(t) // teraz 14:05
	dump := cat.snapshot()
	old := addSegment(t, a, clk, 2)
	a.Cat = dump
	clk.t = clk.t.Add(3 * time.Hour) // 17:05 – przyjęcie trzy godziny później
	res, err := a.Run(ctx, Recovery{Kind: "adopt", Paths: []string{old.Path}})
	if err != nil || len(res.Segments) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	clk.t = clk.t.Add(25 * time.Minute)
	for _, p := range a.Verify(ctx, VerifyOptions{}).Problems {
		if strings.Contains(p, "bez manifestu") {
			t.Fatalf("przyjęty segment zgłoszony jako zaległy: %s", p)
		}
	}
	// Dwie godziny później bez manifestu – to już zaległość.
	clk.t = clk.t.Add(2 * time.Hour)
	mustFail(t, a, "bez manifestu od ponad godziny")
}
