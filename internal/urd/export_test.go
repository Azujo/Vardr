package urd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
)

func buildExport(t *testing.T, a *Archive, from, to time.Time) []byte {
	t.Helper()
	p, err := a.PlanExport(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	j := ExportJob{ID: 7, RequestedBy: "adam", Reason: "kontrola NIS2", From: from, To: to}
	j, err = a.WriteExport(context.Background(), j, p, &buf, ExportOptions{Version: "test", TempDir: t.TempDir(), Enrich: testEnrich})
	if err != nil {
		t.Fatal(err)
	}
	if j.Manifests != 2 || j.Segments != 4 || j.Records != 12 {
		t.Fatalf("statystyki eksportu: %+v", j)
	}
	return buf.Bytes()
}

// rewriteTar przepisuje paczkę, zmieniając wybrane pliki (nil = usunięcie)
// i ewentualnie przeliczając SHA256SUMS (jak zrobiłby to fałszerz).
func rewriteTar(t *testing.T, data []byte, change map[string]func([]byte) []byte, add map[string][]byte, fixSums bool) []byte {
	t.Helper()
	type file struct {
		name string
		data []byte
	}
	var files []file
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		if fn, ok := change[h.Name]; ok {
			if b = fn(b); b == nil {
				continue
			}
		}
		files = append(files, file{h.Name, b})
	}
	for n, b := range add {
		files = append(files[:len(files)-1], file{n, b}, files[len(files)-1])
	}
	if fixSums {
		var sums strings.Builder
		for _, f := range files[:len(files)-1] {
			fmt.Fprintf(&sums, "%s  %s\n", SumHex(f.data), f.name)
		}
		files[len(files)-1].data = []byte(sums.String())
	}
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o444, Size: int64(len(f.data))})
		_, _ = tw.Write(f.data)
	}
	_ = tw.Close()
	return out.Bytes()
}

func expectProblem(t *testing.T, c ExportCheck, want string) {
	t.Helper()
	if c.OK {
		t.Fatalf("sprawdzenie powinno wykryć: %s", want)
	}
	for _, p := range c.Problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("brak problemu %q w %v", want, c.Problems)
}

func TestExportRoundtripAndTamper(t *testing.T) {
	a, _, _ := fillReal(t)
	// Zapis obsługi niezgodności trafia do paczki (obsluga-niezgodnosci/).
	if err := a.LogRecovery(Recovery{ID: 3, Kind: "adopt", Reason: "przywrócenie kopii"}); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour) // godziny 10:00 i 11:00 (z 4 manifestów)
	data := buildExport(t, a, from, to)

	c := CheckExport(bytes.NewReader(data))
	if !c.OK || c.Manifests != 2 || c.Segments != 4 || c.Records != 12 || c.ExportID != 7 {
		t.Fatalf("poprawna paczka: %+v", c)
	}
	if !bytes.Contains(data, []byte("obsluga-niezgodnosci/")) || !bytes.Contains(data, []byte(`"recoveries": 1`)) {
		t.Fatal("brak zapisu obsługi niezgodności w paczce")
	}
	firstSeg := ""
	tr := tar.NewReader(bytes.NewReader(data))
	for h, err := tr.Next(); err == nil; h, err = tr.Next() {
		if strings.HasPrefix(h.Name, "segments/") && firstSeg == "" {
			firstSeg = h.Name
		}
	}
	flip := func(b []byte) []byte { b[len(b)-4] ^= 1; return b }

	t.Run("zmiana segmentu bez poprawienia sum", func(t *testing.T) {
		expectProblem(t, CheckExport(bytes.NewReader(rewriteTar(t, data, map[string]func([]byte) []byte{firstSeg: flip}, nil, false))),
			"niezgodny z SHA256SUMS")
	})
	t.Run("zmiana segmentu z przeliczonymi sumami", func(t *testing.T) {
		c := CheckExport(bytes.NewReader(rewriteTar(t, data, map[string]func([]byte) []byte{firstSeg: flip}, nil, true)))
		expectProblem(t, c, "niezgodny z manifestem")
		expectProblem(t, c, "niezgodnych z ich sumą")
	})
	t.Run("podmiana manifestu w łańcuchu", func(t *testing.T) {
		c := CheckExport(bytes.NewReader(rewriteTar(t, data, map[string]func([]byte) []byte{
			chainName(1): func(b []byte) []byte { return bytes.Replace(b, []byte(`"records": 6`), []byte(`"records": 5`), 1) },
		}, nil, true)))
		expectProblem(t, c, "łańcuch przerwany")
	})
	t.Run("usunięty segment", func(t *testing.T) {
		expectProblem(t, CheckExport(bytes.NewReader(rewriteTar(t, data, map[string]func([]byte) []byte{firstSeg: func([]byte) []byte { return nil }}, nil, true))),
			"brak segmentu")
	})
	t.Run("dodany plik", func(t *testing.T) {
		expectProblem(t, CheckExport(bytes.NewReader(rewriteTar(t, data, nil, map[string][]byte{"segments/obcy.urd": []byte(Magic)}, false))),
			"spoza SHA256SUMS")
	})
}

func TestPlanExportEmptyRange(t *testing.T) {
	a, _, _ := fill(t)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if _, err := a.PlanExport(context.Background(), from, from.Add(time.Hour)); !errors.Is(err, ErrExportEmpty) {
		t.Fatalf("pusty zakres: %v", err)
	}
	if !ValidExportName(ExportName(ExportJob{ID: 3, From: from, To: from.Add(time.Hour)})) || ValidExportName("../../etc/passwd") {
		t.Fatal("walidacja nazwy pliku eksportu")
	}
}

// realBatch buduje paczkę agenta w formacie z załącznika A (gzip + JSON).
func realBatch(t *testing.T, id string, n int) []byte {
	t.Helper()
	b := contract.Batch{Schema: "vardr.batch/1", BatchID: id, AgentID: "agt-1"}
	for i := range n {
		b.Events = append(b.Events, contract.Event{ID: fmt.Sprintf("%s-e%d", id, i), Source: "Security",
			Raw: fmt.Sprintf(`<Event><System><EventID>4625</EventID><Computer>PC-%d</Computer></System><EventData>%s/%d ąę</EventData></Event>`, i, id, i)})
	}
	data, _ := json.Marshal(b)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

// fillReal: jak fill, ale z prawdziwymi paczkami agentów (2 zdarzenia w paczce).
func fillReal(t *testing.T) (*Archive, *MemCatalog, *clock) {
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
				id := fmt.Sprintf("b%d%d%d", h, s, r)
				if err := w.Add(RecordMeta{Agent: "agt-1", Batch: id, ReceivedAt: clk.t}, realBatch(t, id, 2)); err != nil {
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
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	return a, cat, clk
}

func testEnrich(ev contract.Event, _ string, _ time.Time, r *Readable) {
	r.Code, r.HostName = 4625, "pc-z-normalizatora"
}

func tarFile(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	for h, err := tr.Next(); err == nil; h, err = tr.Next() {
		if h.Name == name {
			b, _ := io.ReadAll(tr)
			return b
		}
	}
	t.Fatalf("brak pliku %s w paczce", name)
	return nil
}

func TestExportReadablePart(t *testing.T) {
	a, _, _ := fillReal(t)
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	data := buildExport(t, a, from, from.Add(2*time.Hour))
	c := CheckExport(bytes.NewReader(data))
	if !c.OK || c.Events != 24 {
		t.Fatalf("paczka z częścią czytelną: %+v", c)
	}

	// NDJSON: pola ECS i oryginalny XML.
	gz := tarFile(t, data, "zdarzenia/2026-10-07_10.ndjson.gz")
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	lines, _ := io.ReadAll(zr)
	first := strings.SplitN(string(lines), "\n", 2)[0]
	var ev map[string]any
	if err := json.Unmarshal([]byte(first), &ev); err != nil {
		t.Fatal(err)
	}
	if ev["event.code"] != float64(4625) || ev["host.name"] != "pc-z-normalizatora" || ev["winlog.channel"] != "Security" ||
		!strings.HasPrefix(ev["event.original"].(string), "<Event>") || !strings.Contains(ev["event.original"].(string), "ąę") ||
		ev["vardr.batch_sha256"] == "" {
		t.Fatalf("zdarzenie czytelne: %s", first)
	}

	// CSV: nagłówek + 24 wiersze, BOM dla Excela.
	csvData := tarFile(t, data, "zdarzenia/zdarzenia.csv")
	if !bytes.HasPrefix(csvData, []byte{0xEF, 0xBB, 0xBF}) || strings.Count(string(csvData), "\n") != 25 {
		t.Fatalf("CSV: %q", csvData[:min(len(csvData), 200)])
	}
	if script := tarFile(t, data, "narzedzia/odczytaj_segmenty.py"); !bytes.Contains(script, []byte("HEIMURD1")) {
		t.Fatal("brak skryptu sprawdzającego")
	}

	// Zmiana XML w części czytelnej (z przeliczonymi sumami) jest wykrywana.
	forged := rewriteTar(t, data, map[string]func([]byte) []byte{
		"zdarzenia/2026-10-07_10.ndjson.gz": func(b []byte) []byte {
			zr, _ := gzip.NewReader(bytes.NewReader(b))
			plain, _ := io.ReadAll(zr)
			plain = bytes.Replace(plain, []byte("<EventID>4625"), []byte("<EventID>4624"), 1)
			var out bytes.Buffer
			zw := gzip.NewWriter(&out)
			_, _ = zw.Write(plain)
			_ = zw.Close()
			return out.Bytes()
		},
	}, nil, true)
	expectProblem(t, CheckExport(bytes.NewReader(forged)), "czytelne zdarzenia")
}

func TestExportAgentFilter(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 7, 10, 5, 0, 0, time.UTC)}
	a := New(t.TempDir(), NewMemCatalog())
	a.Now = clk.now
	w, err := a.OpenSegment()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		agent := []string{"agt-1", "agt-2", "agt-3"}[i%3]
		id := fmt.Sprintf("f%d", i)
		if err := w.Add(RecordMeta{Agent: agent, Batch: id, ReceivedAt: clk.t}, realBatch(t, id, 2)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Hour)
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	p, err := a.PlanExport(ctx, from, from.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	j := ExportJob{ID: 8, RequestedBy: "adam", Reason: "incydent na PC-2", From: from, To: from.Add(time.Hour), Agents: []string{"agt-2", "agt-3"}}
	if _, err := a.WriteExport(ctx, j, p, &buf, ExportOptions{Version: "test", TempDir: t.TempDir(), Enrich: testEnrich}); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	c := CheckExport(bytes.NewReader(data))
	// 4 paczki wybranych agentów × 2 zdarzenia; segment (dowód) z wszystkimi 6 paczkami.
	if !c.OK || c.Events != 8 || c.Records != 6 || len(c.Agents) != 2 {
		t.Fatalf("eksport z filtrem agentów: %+v", c)
	}
	csvData := tarFile(t, data, "zdarzenia/zdarzenia.csv")
	if strings.Count(string(csvData), "\n") != 9 || strings.Contains(string(csvData), "agt-1") {
		t.Fatalf("CSV tylko z wybranych agentów: %s", csvData)
	}
	// Usunięcie filtra z export.json (z przeliczonymi sumami) – część czytelna
	// nie odpowiada już deklarowanemu zakresowi.
	forged := rewriteTar(t, data, map[string]func([]byte) []byte{
		"export.json": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"agt-2",`), []byte{}, 1)
		},
	}, nil, true)
	expectProblem(t, CheckExport(bytes.NewReader(forged)), "czytelne zdarzenia")
}
