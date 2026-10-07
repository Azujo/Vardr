package urd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// maxProblems ogranicza listę problemów w wyniku (reszta jest zliczana).
const maxProblems = 200

type problems struct {
	list  []string
	extra int
}

func (p *problems) add(format string, args ...any) {
	if len(p.list) < maxProblems {
		p.list = append(p.list, fmt.Sprintf(format, args...))
		return
	}
	p.extra++
}

func (p *problems) count() int { return len(p.list) + p.extra }

func (p *problems) result() []string {
	out := p.list
	if p.extra > 0 {
		out = append(out, fmt.Sprintf("… oraz %d kolejnych problemów", p.extra))
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// VerifyOptions steruje zakresem weryfikacji.
type VerifyOptions struct {
	// BudgetBytes ogranicza ilość danych czytanych w całości (hash treści)
	// w jednym przebiegu; 0 = całe archiwum. Pierwszeństwo mają manifesty
	// jeszcze niesprawdzone w całości (nowe i te z wykrytymi problemami),
	// potem sprawdzone najdawniej – kolejne przebiegi obejmują całość
	// po kolei. Tanie sprawdzenia (łańcuch, manifesty, obecność i rozmiar
	// każdego segmentu) obejmują zawsze całe archiwum.
	BudgetBytes int64
}

type manifestCheck struct {
	rec  ManifestRecord
	segs []Segment
	full bool
}

// Verify sprawdza integralność archiwum:
//
//   - ciągłość łańcucha manifestów (numery, godziny, hash poprzednika),
//   - zgodność treści manifestu w bazie z jego hashem i z plikiem na dysku,
//   - każdy segment: obecność i rozmiar, a w ramach budżetu także SHA-256
//     pliku, liczbę rekordów i SHA-256 każdej paczki,
//   - pliki na dysku nieznane spisowi (dodane poza archiwizatorem),
//   - przerwę w tworzeniu manifestów (usunięcie końca łańcucha).
//
// Manifest sprawdzony w całości bez problemów dostaje znacznik czasu
// (verified_at); z problemami – nie, więc wraca w kolejnym przebiegu.
//
// Nie wolno jej uruchamiać równolegle z Expire (usunięte pliki wyglądałyby
// na brakujące); równoległe Commit i Seal są bezpieczne.
func (a *Archive) Verify(ctx context.Context, opt VerifyOptions) Verification {
	v := Verification{StartedAt: a.now()}
	var p problems

	// Pliki na dysku zbierane PRZED odczytem spisu: segment zapisany
	// w trakcie weryfikacji nie zostanie wtedy uznany za obcy.
	onDisk, err := a.listFiles()
	if err != nil {
		p.add("odczyt katalogu archiwum: %v", err)
	}
	ms, err := a.Cat.Manifests(ctx)
	if err != nil {
		p.add("odczyt łańcucha manifestów: %v", err)
	}
	known := map[string]bool{}

	// 1. Łańcuch i manifesty (tanie, zawsze całość).
	var checks []*manifestCheck
	prevSHA, prevSeq := GenesisPrev, int64(0)
	var prevHour time.Time
	for i, m := range ms {
		label := fmt.Sprintf("manifest %d (%s)", m.Seq, m.Hour.UTC().Format("2006-01-02 15:00"))
		if m.Seq != prevSeq+1 {
			p.add("luka w łańcuchu: po manifeście %d następuje %d – manifesty usunięte z bazy", prevSeq, m.Seq)
		}
		if i > 0 && !m.Hour.Equal(prevHour.Add(time.Hour)) {
			p.add("%s: brak manifestów między %s a tą godziną", label, prevHour.UTC().Format("2006-01-02 15:00"))
		}
		if m.PrevSHA256 != prevSHA {
			p.add("%s: hash poprzednika nie zgadza się – łańcuch przerwany", label)
		}
		prevSHA, prevSeq, prevHour = m.SHA256, m.Seq, m.Hour
		if m.ExpiredAt != nil {
			continue
		}
		v.Manifests++
		if SumHex(m.Body) != m.SHA256 {
			p.add("%s: treść w bazie nie zgadza się z hashem – zmieniona", label)
		}
		mpath := ManifestPath(m.Hour)
		known[mpath] = true
		if file, err := os.ReadFile(a.abs(mpath)); err != nil {
			p.add("%s: brak pliku %s: %v", label, mpath, err)
		} else if !bytes.Equal(file, m.Body) {
			p.add("%s: plik %s różni się od zapisu w bazie – zmieniony", label, mpath)
		}
		var body Manifest
		if err := json.Unmarshal(m.Body, &body); err != nil {
			p.add("%s: nieczytelna treść: %v", label, err)
			continue
		}
		if body.Seq != m.Seq || !body.Hour.Equal(m.Hour) || body.PrevSHA256 != m.PrevSHA256 {
			p.add("%s: treść nie zgadza się z wpisem w łańcuchu", label)
		}
		for _, s := range body.Segments {
			known[s.Path] = true
		}
		checks = append(checks, &manifestCheck{rec: m, segs: body.Segments})
	}
	if n := len(ms); n > 0 && ms[n-1].Hour.Before(a.now().Truncate(time.Hour).Add(-2*time.Hour)) {
		p.add("ostatni manifest dotyczy godziny %s – archiwizator nie działa albo koniec łańcucha usunięto",
			ms[n-1].Hour.UTC().Format("2006-01-02 15:00"))
	}

	// 2. Wybór manifestów do pełnego sprawdzenia: najpierw niesprawdzone,
	// potem sprawdzone najdawniej, do wyczerpania budżetu (co najmniej jeden).
	order := slices.Clone(checks)
	slices.SortStableFunc(order, func(x, y *manifestCheck) int {
		switch xv, yv := x.rec.VerifiedAt, y.rec.VerifiedAt; {
		case xv == nil && yv == nil:
			return 0
		case xv == nil:
			return -1
		case yv == nil:
			return 1
		}
		return x.rec.VerifiedAt.Compare(*y.rec.VerifiedAt)
	})
	var used int64
	for _, c := range order {
		if opt.BudgetBytes > 0 && used > 0 && used+c.rec.Bytes > opt.BudgetBytes {
			break
		}
		c.full = true
		used += c.rec.Bytes
	}

	// 3. Segmenty: pełne sprawdzenie albo obecność i rozmiar.
	var passed []int64
	for _, c := range checks {
		if ctx.Err() != nil {
			p.add("weryfikacja przerwana: %v", ctx.Err())
			break
		}
		before := p.count()
		for _, s := range c.segs {
			if c.full {
				a.verifySegment(s, &v, &p)
			} else {
				a.statSegment(s, &v, &p)
			}
		}
		if c.full {
			v.FullManifests++
			if p.count() == before {
				passed = append(passed, c.rec.Seq)
			}
		}
	}

	open, err := a.Cat.OpenSegments(ctx)
	if err != nil {
		p.add("odczyt otwartych segmentów: %v", err)
	}
	stale := a.now().Truncate(time.Hour).Add(-time.Hour)
	for _, s := range open {
		known[s.Path] = true
		a.verifySegment(s, &v, &p)
		if s.Hour.Before(stale) {
			p.add("segment %s bez manifestu od ponad godziny", s.Path)
		}
	}

	var unknown []string
	for _, f := range onDisk {
		if !known[f] {
			unknown = append(unknown, f)
		}
	}
	if len(unknown) > 0 {
		// Segment mógł zostać zarejestrowany między listowaniem a odczytem spisu.
		if again, err := a.Cat.OpenSegments(ctx); err == nil {
			for _, s := range again {
				known[s.Path] = true
			}
		}
		for _, f := range unknown {
			if !known[f] {
				p.add("plik %s nie występuje w spisie archiwum – dodany poza archiwizatorem", f)
			}
		}
	}

	now := a.now()
	if len(passed) > 0 {
		if err := a.Cat.MarkVerified(ctx, passed, now); err != nil {
			p.add("zapis znaczników pełnego sprawdzenia: %v", err)
		}
	}
	// Pokrycie: najdawniejsze pełne sprawdzenie danych w retencji (brak,
	// gdy część danych nie była jeszcze sprawdzona w całości).
	passedSet := map[int64]bool{}
	for _, s := range passed {
		passedSet[s] = true
	}
	covered := true
	var oldest *time.Time
	for _, c := range checks {
		at := c.rec.VerifiedAt
		if passedSet[c.rec.Seq] {
			at = &now
		}
		if at == nil {
			covered = false
			v.Unverified++
			continue
		}
		if oldest == nil || at.Before(*oldest) {
			t := *at
			oldest = &t
		}
	}
	if covered {
		v.OldestFullCheck = oldest
	}

	v.Problems = p.result()
	v.OK = len(v.Problems) == 0
	v.FinishedAt = a.now()
	return v
}

// statSegment sprawdza obecność i rozmiar segmentu (bez czytania treści).
func (a *Archive) statSegment(s Segment, v *Verification, p *problems) {
	v.Segments++
	st, err := os.Stat(a.abs(s.Path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		p.add("segment %s: brak pliku – usunięty", s.Path)
	case err != nil:
		p.add("segment %s: %v", s.Path, err)
	case st.Size() != s.Bytes:
		p.add("segment %s: rozmiar %d B, w spisie %d B", s.Path, st.Size(), s.Bytes)
	}
}

// verifySegment czyta segment w całości i porównuje ze spisem.
func (a *Archive) verifySegment(s Segment, v *Verification, p *problems) {
	v.Segments++
	f, err := os.Open(a.abs(s.Path))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			p.add("segment %s: brak pliku – usunięty", s.Path)
		} else {
			p.add("segment %s: %v", s.Path, err)
		}
		return
	}
	defer f.Close()
	h := sha256.New()
	cr := &countingReader{r: io.TeeReader(f, h)}
	records, damaged := 0, 0
	r, err := NewReader(cr)
	if err != nil {
		p.add("segment %s: %v", s.Path, err)
	} else {
		for {
			meta, payload, err := r.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				p.add("segment %s: rekord %d: %v", s.Path, records+1, err)
				break
			}
			records++
			if SumHex(payload) != meta.SHA256 || len(payload) != meta.Bytes {
				damaged++
			}
		}
	}
	_, _ = io.Copy(io.Discard, cr) // reszta pliku do hasha (np. po uszkodzeniu)
	v.Records += int64(records)
	v.Bytes += cr.n
	if damaged > 0 {
		p.add("segment %s: %d paczek niezgodnych z ich sumą SHA-256", s.Path, damaged)
	}
	if cr.n != s.Bytes {
		p.add("segment %s: rozmiar %d B, w spisie %d B", s.Path, cr.n, s.Bytes)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != s.SHA256 {
		p.add("segment %s: SHA-256 pliku nie zgadza się ze spisem – zmieniony", s.Path)
	}
	if records != s.Records {
		p.add("segment %s: %d paczek, w spisie %d", s.Path, records, s.Records)
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// listFiles zwraca pliki segmentów i manifestów (ścieżki względne, bez *.tmp).
func (a *Archive) listFiles() ([]string, error) {
	var out []string
	for _, sub := range []string{"segments", "manifests"} {
		root := filepath.Join(a.Dir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == root {
					return nil
				}
				return err
			}
			if d.IsDir() || strings.HasSuffix(p, ".tmp") {
				return nil
			}
			rel, err := filepath.Rel(a.Dir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
