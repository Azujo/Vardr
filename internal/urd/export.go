package urd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Stany zlecenia eksportu.
const (
	ExportPending = "pending"
	ExportRunning = "running"
	ExportDone    = "done"
	ExportFailed  = "failed"
	ExportExpired = "expired"
)

// MaxExportRange ogranicza zakres jednego eksportu.
const MaxExportRange = 31 * 24 * time.Hour

// ExportFormat identyfikuje wersję paczki eksportu.
const ExportFormat = "heimdall-urd-export/1"

// ExportJob to zlecenie eksportu dla audytora: pełne godziny archiwizacji
// [From, To), oryginalne segmenty z łańcuchem manifestów.
type ExportJob struct {
	ID          int64      `json:"id"`
	RequestedAt time.Time  `json:"requested_at"`
	RequestedBy string     `json:"requested_by"`
	Reason      string     `json:"reason"`
	From        time.Time  `json:"from"`
	To          time.Time  `json:"to"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	FileName    string     `json:"file_name,omitempty"`
	Bytes       int64      `json:"bytes"`
	SHA256      string     `json:"sha256,omitempty"`
	Manifests   int        `json:"manifests"`
	Segments    int        `json:"segments"`
	Records     int64      `json:"records"`
}

// exportNameRe: jedyna dopuszczalna postać nazwy pliku eksportu (panel nie
// poda ścieżki spoza katalogu eksportów).
var exportNameRe = regexp.MustCompile(`^urd-eksport-[0-9]+-[0-9]{10}-[0-9]{10}\.tar$`)

// ValidExportName sprawdza nazwę pliku eksportu.
func ValidExportName(name string) bool { return exportNameRe.MatchString(name) }

// ExportName buduje nazwę pliku eksportu.
func ExportName(j ExportJob) string {
	return fmt.Sprintf("urd-eksport-%d-%s-%s.tar", j.ID, j.From.UTC().Format("2006010215"), j.To.UTC().Format("2006010215"))
}

// ExportPlan to zawartość eksportu ustalona przed zapisem.
type ExportPlan struct {
	InRange []ManifestRecord // manifesty godzin z zakresu (z danymi)
	Chain   []ManifestRecord // od pierwszego w zakresie do najnowszego (kotwica)
	Bodies  map[int64]Manifest
	Bytes   int64 // dane segmentów
}

// ErrExportEmpty: w zakresie nie ma zamkniętych godzin z danymi w retencji.
var ErrExportEmpty = errors.New("w wybranym zakresie nie ma zamkniętych godzin archiwum z danymi w retencji")

// PlanExport wybiera manifesty z zakresu i ogon łańcucha do najnowszego.
func (a *Archive) PlanExport(ctx context.Context, from, to time.Time) (ExportPlan, error) {
	p := ExportPlan{Bodies: map[int64]Manifest{}}
	ms, err := a.Cat.Manifests(ctx)
	if err != nil {
		return p, err
	}
	first := -1
	for i, m := range ms {
		if m.ExpiredAt != nil || m.Hour.Before(from) || !m.Hour.Before(to) {
			continue
		}
		if first < 0 {
			first = i
		}
		p.InRange = append(p.InRange, m)
		p.Bytes += m.Bytes
	}
	if first < 0 {
		return p, ErrExportEmpty
	}
	p.Chain = ms[first:]
	for _, m := range p.Chain {
		var body Manifest
		if m.Body == nil || json.Unmarshal(m.Body, &body) != nil {
			return p, fmt.Errorf("manifest %d: brak lub nieczytelna treść w spisie", m.Seq)
		}
		p.Bodies[m.Seq] = body
	}
	return p, nil
}

// exportInfo to plik export.json w paczce.
type exportInfo struct {
	Format        string          `json:"format"`
	ExportID      int64           `json:"export_id"`
	RequestedBy   string          `json:"requested_by"`
	Reason        string          `json:"reason"`
	RequestedAt   time.Time       `json:"requested_at"`
	CreatedAt     time.Time       `json:"created_at"`
	ServerVersion string          `json:"server_version"`
	From          time.Time       `json:"from"`
	To            time.Time       `json:"to"`
	Manifests     []exportRef     `json:"manifests"`
	Latest        exportRef       `json:"latest_manifest"`
	Totals        exportTotals    `json:"totals"`
	Note          string          `json:"note"`
	Chain         exportChainSpan `json:"chain"`
}

type exportRef struct {
	Seq    int64     `json:"seq"`
	Hour   time.Time `json:"hour"`
	SHA256 string    `json:"sha256"`
}

type exportTotals struct {
	Segments int   `json:"segments"`
	Records  int64 `json:"records"`
	Bytes    int64 `json:"bytes"`
}

type exportChainSpan struct {
	FromSeq int64 `json:"from_seq"`
	ToSeq   int64 `json:"to_seq"`
}

func chainName(seq int64) string { return fmt.Sprintf("chain/%08d.json", seq) }

// WriteExport zapisuje paczkę eksportu (tar) do w. Każdy segment jest przy
// zapisie porównywany z sumą z manifestu – uszkodzone archiwum przerywa
// eksport (najpierw trzeba wyjaśnić niezgodność).
func (a *Archive) WriteExport(ctx context.Context, j ExportJob, p ExportPlan, w io.Writer, version string) (ExportJob, error) {
	now := a.now()
	tw := tar.NewWriter(w)
	var sums bytes.Buffer
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: int64(len(data)), ModTime: now, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%s  %s\n", SumHex(data), name)
		return nil
	}

	info := exportInfo{Format: ExportFormat, ExportID: j.ID, RequestedBy: j.RequestedBy, Reason: j.Reason,
		RequestedAt: j.RequestedAt, CreatedAt: now, ServerVersion: version, From: j.From.UTC(), To: j.To.UTC(),
		Note:  "Zakres dotyczy godzin archiwizacji (czasu przyjęcia paczek przez serwer), nie czasu zdarzeń.",
		Chain: exportChainSpan{FromSeq: p.Chain[0].Seq, ToSeq: p.Chain[len(p.Chain)-1].Seq}}
	for _, m := range p.InRange {
		info.Manifests = append(info.Manifests, exportRef{m.Seq, m.Hour.UTC(), m.SHA256})
		info.Totals.Segments += m.Segments
		info.Totals.Records += m.Records
		info.Totals.Bytes += m.Bytes
	}
	last := p.Chain[len(p.Chain)-1]
	info.Latest = exportRef{last.Seq, last.Hour.UTC(), last.SHA256}
	infoJSON, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return j, err
	}
	if err := add("README.txt", []byte(exportReadme)); err != nil {
		return j, err
	}
	if err := add("export.json", append(infoJSON, '\n')); err != nil {
		return j, err
	}
	for _, m := range p.Chain {
		if err := add(chainName(m.Seq), m.Body); err != nil {
			return j, err
		}
	}
	for _, m := range p.InRange {
		for _, s := range p.Bodies[m.Seq].Segments {
			if ctx.Err() != nil {
				return j, ctx.Err()
			}
			if err := a.addSegment(tw, &sums, s, now); err != nil {
				return j, err
			}
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "SHA256SUMS", Mode: 0o444, Size: int64(sums.Len()), ModTime: now, Format: tar.FormatPAX}); err != nil {
		return j, err
	}
	if _, err := tw.Write(sums.Bytes()); err != nil {
		return j, err
	}
	if err := tw.Close(); err != nil {
		return j, err
	}
	j.Manifests, j.Segments, j.Records = len(p.InRange), info.Totals.Segments, info.Totals.Records
	return j, nil
}

func (a *Archive) addSegment(tw *tar.Writer, sums *bytes.Buffer, s Segment, now time.Time) error {
	f, err := os.Open(a.abs(s.Path))
	if err != nil {
		return fmt.Errorf("segment %s: %w", s.Path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != s.Bytes {
		return fmt.Errorf("segment %s: rozmiar %d B zamiast %d B – archiwum niezgodne, uruchom weryfikację", s.Path, st.Size(), s.Bytes)
	}
	if err := tw.WriteHeader(&tar.Header{Name: s.Path, Mode: 0o444, Size: s.Bytes, ModTime: now, Format: tar.FormatPAX}); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(tw, io.TeeReader(f, h)); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sum != s.SHA256 {
		return fmt.Errorf("segment %s: SHA-256 niezgodny z manifestem – archiwum niezgodne, uruchom weryfikację", s.Path)
	}
	fmt.Fprintf(sums, "%s  %s\n", sum, s.Path)
	return nil
}

// ExportCheck to wynik sprawdzenia paczki eksportu.
type ExportCheck struct {
	OK        bool     `json:"ok"`
	ExportID  int64    `json:"export_id"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Manifests int      `json:"manifests"`
	Segments  int      `json:"segments"`
	Records   int64    `json:"records"`
	Latest    string   `json:"latest_manifest_sha256"`
	Problems  []string `json:"problems"`
}

// CheckExport sprawdza paczkę eksportu bez dostępu do systemu:
//   - sumy z SHA256SUMS dla każdego pliku (i brak plików spoza listy),
//   - łańcuch manifestów (hash poprzednika każdego ogniwa),
//   - zgodność manifestów z listy z export.json,
//   - każdy segment: SHA-256 i rozmiar z manifestu, liczba paczek i suma
//     każdej paczki.
//
// Kotwicę (hash najnowszego manifestu) warto porównać z wartością
// zapisaną niezależnie, np. w protokole przekazania.
func CheckExport(r io.Reader) ExportCheck {
	var c ExportCheck
	var p problems
	type segInfo struct {
		sum             string
		size            int64
		records, broken int
		err             error
	}
	sums := map[string]string{}
	chain := map[int64][]byte{}
	segs := map[string]segInfo{}
	var info exportInfo
	var sumsFile []byte

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.add("paczka nieczytelna: %v", err)
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			p.add("nieoczekiwany wpis %s", hdr.Name)
			continue
		}
		name := hdr.Name
		h := sha256.New()
		body := io.TeeReader(tr, h)
		switch {
		case strings.HasPrefix(name, "segments/"):
			si := segInfo{}
			cr := &countingReader{r: body}
			if rd, err := NewReader(cr); err != nil {
				si.err = err
			} else {
				for {
					meta, payload, err := rd.Next()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						si.err = err
						break
					}
					si.records++
					if SumHex(payload) != meta.SHA256 || len(payload) != meta.Bytes {
						si.broken++
					}
				}
			}
			_, _ = io.Copy(io.Discard, cr)
			si.size = cr.n
			si.sum = hex.EncodeToString(h.Sum(nil))
			segs[name] = si
			sums[name] = si.sum
		default:
			data, err := io.ReadAll(body)
			if err != nil {
				p.add("%s: %v", name, err)
				continue
			}
			if name == "SHA256SUMS" {
				sumsFile = data
				continue
			}
			sums[name] = hex.EncodeToString(h.Sum(nil))
			switch {
			case name == "export.json":
				if err := json.Unmarshal(data, &info); err != nil {
					p.add("export.json nieczytelny: %v", err)
				}
			case strings.HasPrefix(name, "chain/"):
				var seq int64
				if _, err := fmt.Sscanf(path.Base(name), "%08d.json", &seq); err != nil {
					p.add("nieoczekiwany plik %s", name)
				}
				chain[seq] = data
			}
		}
	}

	// SHA256SUMS: każdy plik na liście i z właściwą sumą, nic spoza listy.
	if sumsFile == nil {
		p.add("brak pliku SHA256SUMS")
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(sumsFile)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			continue
		}
		listed[name] = true
		if got, ok := sums[name]; !ok {
			p.add("brak pliku %s wymienionego w SHA256SUMS", name)
		} else if got != sum {
			p.add("plik %s: SHA-256 niezgodny z SHA256SUMS – zmieniony", name)
		}
	}
	for name := range sums {
		if !listed[name] {
			p.add("plik %s spoza SHA256SUMS – dodany", name)
		}
	}

	if info.Format != ExportFormat {
		p.add("nieznany format paczki: %q", info.Format)
	}
	c.ExportID, c.From, c.To = info.ExportID, info.From.Format(time.RFC3339), info.To.Format(time.RFC3339)
	c.Latest = info.Latest.SHA256

	// Łańcuch: kolejne ogniwa od from_seq do to_seq.
	var bodies = map[int64]Manifest{}
	prev := ""
	for seq := info.Chain.FromSeq; seq <= info.Chain.ToSeq && seq > 0; seq++ {
		data, ok := chain[seq]
		if !ok {
			p.add("brak manifestu %d w łańcuchu", seq)
			prev = ""
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil || m.Seq != seq {
			p.add("manifest %d nieczytelny", seq)
			prev = ""
			continue
		}
		if prev != "" && m.PrevSHA256 != prev {
			p.add("manifest %d: hash poprzednika nie zgadza się – łańcuch przerwany", seq)
		}
		prev = SumHex(data)
		bodies[seq] = m
		if seq == info.Chain.ToSeq && prev != info.Latest.SHA256 {
			p.add("najnowszy manifest nie zgadza się z kotwicą w export.json")
		}
	}
	if len(chain) != len(bodies) && len(bodies) > 0 {
		p.add("w paczce są manifesty spoza zakresu łańcucha")
	}

	// Segmenty manifestów z zakresu.
	expected := map[string]bool{}
	for _, ref := range info.Manifests {
		m, ok := bodies[ref.Seq]
		if !ok {
			continue
		}
		if SumHex(chain[ref.Seq]) != ref.SHA256 {
			p.add("manifest %d: hash niezgodny z export.json", ref.Seq)
		}
		c.Manifests++
		for _, s := range m.Segments {
			expected[s.Path] = true
			si, ok := segs[s.Path]
			switch {
			case !ok:
				p.add("brak segmentu %s", s.Path)
				continue
			case si.err != nil:
				p.add("segment %s: %v", s.Path, si.err)
			case si.sum != s.SHA256 || si.size != s.Bytes:
				p.add("segment %s: SHA-256 lub rozmiar niezgodny z manifestem – zmieniony", s.Path)
			case si.records != s.Records:
				p.add("segment %s: %d paczek zamiast %d", s.Path, si.records, s.Records)
			}
			if si.broken > 0 {
				p.add("segment %s: %d paczek niezgodnych z ich sumą SHA-256", s.Path, si.broken)
			}
			c.Segments++
			c.Records += int64(si.records)
		}
	}
	extra := []string{}
	for name := range segs {
		if !expected[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		p.add("segment %s nie należy do żadnego manifestu z zakresu", name)
	}

	c.Problems = p.result()
	c.OK = len(c.Problems) == 0
	return c
}

const exportReadme = `Heimdall – eksport archiwum NIS2 (Urd) dla audytora
=====================================================

Zawartość paczki:
  export.json   opis eksportu: kto, kiedy i w jakim celu zlecił, zakres godzin,
                manifesty z zakresu i kotwica (hash najnowszego manifestu)
  chain/        manifesty godzinowe od pierwszej godziny zakresu do najnowszej,
                w dokładnie tej postaci, w jakiej zapisał je archiwizator
  segments/     oryginalne segmenty archiwum (paczki agentów w postaci,
                w jakiej przyszły na serwer, przed jakąkolwiek obróbką)
  SHA256SUMS    sumy SHA-256 wszystkich plików powyżej

Jak sprawdzić integralność:
  1. sha256sum -c SHA256SUMS  – żaden plik nie został zmieniony.
  2. Każdy manifest w chain/ zawiera "prev_sha256" równy SHA-256 pliku
     poprzedniego manifestu – manifesty tworzą łańcuch.
  3. Każdy segment w segments/ ma SHA-256 i rozmiar równe wpisowi w swoim
     manifeście.
  4. SHA-256 najnowszego manifestu (latest_manifest w export.json) warto
     porównać z wartością zapisaną niezależnie (np. w protokole przekazania
     albo w wydruku z panelu z dnia eksportu).

Wszystkie kroki wykonuje automatycznie polecenie:
  siem-archiver check-export <plik.tar>

Format segmentu: nagłówek "HEIMURD1", potem rekordy: uint32 BE długość
metadanych, metadane JSON (agent, identyfikator paczki, czas przyjęcia,
SHA-256 treści), uint32 BE długość treści, treść (paczka agenta, zwykle gzip).

Zakres eksportu dotyczy godzin archiwizacji (czasu przyjęcia paczek przez
serwer), nie czasu zdarzeń zapisanego w logach.
`
