package urd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func buildExport(t *testing.T, a *Archive, from, to time.Time) []byte {
	t.Helper()
	p, err := a.PlanExport(context.Background(), from, to)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	j := ExportJob{ID: 7, RequestedBy: "adam", Reason: "kontrola NIS2", From: from, To: to}
	j, err = a.WriteExport(context.Background(), j, p, &buf, "test")
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
	a, _, _ := fill(t)
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour) // godziny 10:00 i 11:00 (z 4 manifestów)
	data := buildExport(t, a, from, to)

	c := CheckExport(bytes.NewReader(data))
	if !c.OK || c.Manifests != 2 || c.Segments != 4 || c.Records != 12 || c.ExportID != 7 {
		t.Fatalf("poprawna paczka: %+v", c)
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
