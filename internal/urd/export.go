// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"siem/internal/lang"
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

// ExportFormat identyfikuje wersję paczki eksportu. /3 różni się od /2
// tylko nazwą (pola vardr.* zamiast heimdall.*); starsze paczki są nadal
// sprawdzane i czytane.
const ExportFormat = "vardr-urd-export/3"

// Wcześniejsze formaty eksportu (sprzed zmiany nazwy na Vardr).
const (
	exportFormatV1 = "heimdall-urd-export/1" // bez czytelnych zdarzeń do porównania
	exportFormatV2 = "heimdall-urd-export/2"
)

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
	// Agents: część czytelna tylko z tych agentów (puste = wszyscy).
	// Segmenty (dowód) zawsze są kompletne – tylko całe segmenty można
	// sprawdzić względem manifestu.
	Agents []string `json:"agents"`
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
var ErrExportEmpty = lang.Errorf("w wybranym zakresie nie ma zamkniętych godzin archiwum z danymi w retencji",
	"the selected range has no closed archive hours with data within retention")

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
			return p, lang.Errorf("manifest %d: brak lub nieczytelna treść w spisie", "manifest %d: content missing or unreadable in the catalog", m.Seq)
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
	Agents        []string        `json:"agents,omitempty"` // część czytelna tylko z tych agentów
	Manifests     []exportRef     `json:"manifests"`
	Latest        exportRef       `json:"latest_manifest"`
	Totals        exportTotals    `json:"totals"`
	Readable      exportReadable  `json:"readable"`
	Tools         []string        `json:"tools,omitempty"`
	Note          string          `json:"note"`
	Chain         exportChainSpan `json:"chain"`
	// Recoveries: liczba zapisów obsługi niezgodności (obsluga-niezgodnosci/).
	Recoveries int `json:"recoveries,omitempty"`
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

// exportReadable opisuje czytelną część paczki (zdarzenia/).
type exportReadable struct {
	Events       int64    `json:"events"`
	Unreadable   int64    `json:"unreadable_batches"`
	Files        []string `json:"files"`
	CSVRows      int      `json:"csv_rows"`
	CSVTruncated bool     `json:"csv_truncated"`
}

type exportChainSpan struct {
	FromSeq int64 `json:"from_seq"`
	ToSeq   int64 `json:"to_seq"`
}

func chainName(seq int64) string { return fmt.Sprintf("chain/%08d.json", seq) }

// ExportOptions to parametry zapisu paczki.
type ExportOptions struct {
	Version string
	// TempDir: katalog plików roboczych (czytelne zdarzenia są zapisywane
	// najpierw do pliku – nagłówek tar wymaga rozmiaru z góry).
	TempDir string
	Enrich  Enricher
	// Tools: programy dołączane w katalogu głównym paczki (nazwa → plik),
	// np. odczytaj.exe – czytnik eksportu dla odbiorcy.
	Tools map[string]string
}

// WriteExport zapisuje paczkę eksportu (tar) do w:
//
//   - segments/ i chain/ – oryginały i łańcuch manifestów (dowód),
//   - zdarzenia/ – te same zdarzenia w czytelnej postaci (NDJSON z polami ECS
//     i oryginalnym XML, CSV dla arkusza) – do odczytu bez Vardra,
//   - narzedzia/ – niezależny skrypt sprawdzający (Python, biblioteka standardowa).
//
// Każdy segment jest przy zapisie porównywany z sumą z manifestu – uszkodzone
// archiwum przerywa eksport (najpierw trzeba wyjaśnić niezgodność).
func (a *Archive) WriteExport(ctx context.Context, j ExportJob, p ExportPlan, w io.Writer, opt ExportOptions) (ExportJob, error) {
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
		RequestedAt: j.RequestedAt, CreatedAt: now, ServerVersion: opt.Version, From: j.From.UTC(), To: j.To.UTC(),
		Agents: j.Agents,
		Note: a.tr("Zakres dotyczy godzin archiwizacji (czasu przyjęcia paczek przez serwer), nie czasu zdarzeń.",
			"The range refers to archiving hours (when the server accepted the batches), not event time."),
		Chain: exportChainSpan{FromSeq: p.Chain[0].Seq, ToSeq: p.Chain[len(p.Chain)-1].Seq}}
	for _, m := range p.InRange {
		info.Manifests = append(info.Manifests, exportRef{m.Seq, m.Hour.UTC(), m.SHA256})
		info.Totals.Segments += m.Segments
		info.Totals.Records += m.Records
		info.Totals.Bytes += m.Bytes
	}
	last := p.Chain[len(p.Chain)-1]
	info.Latest = exportRef{last.Seq, last.Hour.UTC(), last.SHA256}

	// 1. Dowód: łańcuch manifestów i oryginalne segmenty.
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

	// 1a. Obsługa niezgodności (przyjęcia plików do spisu, kwarantanna) –
	// audytor widzi, jak rozstrzygnięto każdą wykrytą niezgodność.
	logs, _ := filepath.Glob(filepath.Join(a.Dir, RecoveryLogDir, "*.json"))
	sort.Strings(logs)
	for _, f := range logs {
		data, err := os.ReadFile(f)
		if err != nil {
			return j, err
		}
		if err := add("obsluga-niezgodnosci/"+filepath.Base(f), data); err != nil {
			return j, err
		}
	}
	info.Recoveries = len(logs)

	// 2. Czytelne zdarzenia: plik NDJSON (gzip) na godzinę i jeden CSV.
	csvFile, err := os.CreateTemp(opt.TempDir, "urd-csv-*")
	if err != nil {
		return j, err
	}
	defer os.Remove(csvFile.Name())
	defer csvFile.Close()
	sink, err := newCSVSink(csvFile, a.lang())
	if err != nil {
		return j, err
	}
	for _, m := range p.InRange {
		name := readableName(m.Hour)
		if err := a.addReadableHour(ctx, tw, &sums, name, p.Bodies[m.Seq].Segments, j.Agents, opt, sink, &info.Readable, now); err != nil {
			return j, err
		}
		info.Readable.Files = append(info.Readable.Files, name)
	}
	if err := sink.close(); err != nil {
		return j, err
	}
	info.Readable.CSVRows, info.Readable.CSVTruncated = sink.rows, sink.full
	if err := addFile(tw, &sums, "zdarzenia/zdarzenia.csv", csvFile, now); err != nil {
		return j, err
	}

	// 3. Narzędzie, opis i spis sum.
	names := slices.Sorted(maps.Keys(opt.Tools))
	for _, name := range names {
		f, err := os.Open(opt.Tools[name])
		if err != nil {
			return j, lang.Errorf("narzędzie %s: %w", "tool %s: %w", name, err)
		}
		err = addFile(tw, &sums, name, f, now)
		f.Close()
		if err != nil {
			return j, err
		}
	}
	info.Tools = names
	if err := add("narzedzia/odczytaj_segmenty.py", readerScript); err != nil {
		return j, err
	}
	infoJSON, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return j, err
	}
	if err := add("export.json", append(infoJSON, '\n')); err != nil {
		return j, err
	}
	if err := add("README.txt", []byte(exportReadme)); err != nil {
		return j, err
	}
	if err := add("README-EN.txt", []byte(exportReadmeEn)); err != nil {
		return j, err
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

// addReadableHour zapisuje czytelne zdarzenia jednej godziny do pliku
// roboczego (gzip), a potem dołącza go do paczki.
func (a *Archive) addReadableHour(ctx context.Context, tw *tar.Writer, sums *bytes.Buffer, name string, segs []Segment,
	agents []string, opt ExportOptions, sink *csvSink, stats *exportReadable, now time.Time) error {
	tmp, err := os.CreateTemp(opt.TempDir, "urd-ndjson-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	zw := gzip.NewWriter(tmp)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	for _, s := range segs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := a.forEachRecord(s, func(meta RecordMeta, payload []byte) error {
			if !agentSelected(agents, meta.Agent) {
				return nil
			}
			for _, r := range readableEvents(meta, payload, opt.Enrich) {
				if r.Error != "" {
					stats.Unreadable++
				} else {
					stats.Events++
				}
				if err := enc.Encode(r); err != nil {
					return err
				}
				if err := sink.add(r); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return addFile(tw, sums, name, tmp, now)
}

// agentSelected: czy paczka agenta należy do części czytelnej (puste = wszyscy).
func agentSelected(agents []string, agent string) bool {
	return len(agents) == 0 || slices.Contains(agents, agent)
}

// forEachRecord czyta rekordy segmentu (sumy sprawdzono przy kopiowaniu).
func (a *Archive) forEachRecord(s Segment, fn func(RecordMeta, []byte) error) error {
	f, err := os.Open(a.abs(s.Path))
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := NewReader(f)
	if err != nil {
		return err
	}
	for {
		meta, payload, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("segment %s: %w", s.Path, err)
		}
		if err := fn(meta, payload); err != nil {
			return err
		}
	}
}

// addFile dołącza do paczki plik roboczy (od początku).
func addFile(tw *tar.Writer, sums *bytes.Buffer, name string, f *os.File, now time.Time) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o444, Size: st.Size(), ModTime: now, Format: tar.FormatPAX}); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(tw, io.TeeReader(f, h)); err != nil {
		return err
	}
	fmt.Fprintf(sums, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), name)
	return nil
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
		return lang.Errorf("segment %s: rozmiar %d B zamiast %d B – archiwum niezgodne, uruchom weryfikację",
			"segment %s: size %d B instead of %d B – archive inconsistent, run verification", s.Path, st.Size(), s.Bytes)
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
		return lang.Errorf("segment %s: SHA-256 niezgodny z manifestem – archiwum niezgodne, uruchom weryfikację",
			"segment %s: SHA-256 does not match the manifest – archive inconsistent, run verification", s.Path)
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
	Events    int64    `json:"events"`
	Agents    []string `json:"agents,omitempty"` // eksport ograniczony do tych agentów
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
// lang: język opisów problemów (pl, en).
func CheckExport(r io.Reader, lang string) ExportCheck {
	tr := tar.NewReader(r)
	return checkEntries(lang, func() (string, io.Reader, error) {
		for {
			hdr, err := tr.Next()
			if err != nil {
				return "", nil, err
			}
			switch hdr.Typeflag {
			case tar.TypeDir:
				continue
			case tar.TypeReg:
				return hdr.Name, tr, nil
			}
			return hdr.Name, nil, nil
		}
	})
}

// ReadOutputDir to podfolder, w którym czytnik eksportu (odczytaj.exe)
// zapisuje swoje wyniki – nie jest częścią paczki i nie podlega sprawdzeniu.
const ReadOutputDir = "ODCZYT"

// CheckExportDir sprawdza rozpakowaną paczkę (folder) tak samo jak CheckExport.
// Podfolder ODCZYT (wyniki czytnika) jest pomijany.
func CheckExportDir(dir, l string) ExportCheck {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ReadOutputDir {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return ExportCheck{Problems: []string{lang.Pick(l, "odczyt folderu: ", "reading the folder: ") + err.Error()}}
	}
	sort.Strings(files)
	var cur *os.File
	i := 0
	c := checkEntries(l, func() (string, io.Reader, error) {
		if cur != nil {
			cur.Close()
			cur = nil
		}
		if i >= len(files) {
			return "", nil, io.EOF
		}
		name := files[i]
		i++
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return "", nil, err
		}
		cur = f
		return name, f, nil
	})
	if cur != nil {
		cur.Close()
	}
	return c
}

// checkEntries sprawdza kolejne pliki paczki (z tar albo z folderu).
func checkEntries(l string, next func() (string, io.Reader, error)) ExportCheck {
	var c ExportCheck
	p := problems{lang: l}
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
	var readDigest eventDigest
	origByAgent := map[string]*eventDigest{} // oryginały według agenta (filtr z export.json)

	for {
		name, rd, err := next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			p.add("paczka nieczytelna: %v", "unreadable package: %v", err)
			break
		}
		if rd == nil {
			p.add("nieoczekiwany wpis %s", "unexpected entry %s", name)
			continue
		}
		h := sha256.New()
		body := io.TeeReader(rd, h)
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
						continue
					}
					if b, err := DecodeBatch(payload); err == nil {
						sum := SumHex(payload)
						d := origByAgent[meta.Agent]
						if d == nil {
							d = &eventDigest{}
							origByAgent[meta.Agent] = d
						}
						for _, ev := range b.Events {
							d.add(sum, ev.ID, ev.Raw)
						}
					}
				}
			}
			_, _ = io.Copy(io.Discard, cr)
			si.size = cr.n
			si.sum = hex.EncodeToString(h.Sum(nil))
			segs[name] = si
			sums[name] = si.sum
		case strings.HasPrefix(name, "zdarzenia/") && strings.HasSuffix(name, ".ndjson.gz"):
			if err := readableDigestOf(body, &readDigest); err != nil {
				p.add("%s: %v", "%s: %v", name, err)
			}
			_, _ = io.Copy(io.Discard, body)
			sums[name] = hex.EncodeToString(h.Sum(nil))
		case strings.HasPrefix(name, "zdarzenia/"):
			_, _ = io.Copy(io.Discard, body)
			sums[name] = hex.EncodeToString(h.Sum(nil))
		default:
			data, err := io.ReadAll(body)
			if err != nil {
				p.add("%s: %v", "%s: %v", name, err)
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
					p.add("export.json nieczytelny: %v", "export.json is unreadable: %v", err)
				}
			case strings.HasPrefix(name, "chain/"):
				var seq int64
				if _, err := fmt.Sscanf(path.Base(name), "%08d.json", &seq); err != nil {
					p.add("nieoczekiwany plik %s", "unexpected file %s", name)
				}
				chain[seq] = data
			}
		}
	}

	// SHA256SUMS: każdy plik na liście i z właściwą sumą, nic spoza listy.
	if sumsFile == nil {
		p.add("brak pliku SHA256SUMS", "SHA256SUMS file missing")
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(sumsFile)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			continue
		}
		listed[name] = true
		if got, ok := sums[name]; !ok {
			p.add("brak pliku %s wymienionego w SHA256SUMS", "file %s listed in SHA256SUMS is missing", name)
		} else if got != sum {
			p.add("plik %s: SHA-256 niezgodny z SHA256SUMS – zmieniony", "file %s: SHA-256 does not match SHA256SUMS – modified", name)
		}
	}
	for name := range sums {
		if !listed[name] {
			p.add("plik %s spoza SHA256SUMS – dodany", "file %s not in SHA256SUMS – added", name)
		}
	}

	if info.Format != ExportFormat && info.Format != exportFormatV2 && info.Format != exportFormatV1 {
		p.add("nieznany format paczki: %q", "unknown package format: %q", info.Format)
	}
	c.ExportID, c.From, c.To = info.ExportID, info.From.Format(time.RFC3339), info.To.Format(time.RFC3339)
	c.Latest = info.Latest.SHA256

	// Łańcuch: kolejne ogniwa od from_seq do to_seq.
	var bodies = map[int64]Manifest{}
	prev := ""
	for seq := info.Chain.FromSeq; seq <= info.Chain.ToSeq && seq > 0; seq++ {
		data, ok := chain[seq]
		if !ok {
			p.add("brak manifestu %d w łańcuchu", "manifest %d missing from the chain", seq)
			prev = ""
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil || m.Seq != seq {
			p.add("manifest %d nieczytelny", "manifest %d is unreadable", seq)
			prev = ""
			continue
		}
		if prev != "" && m.PrevSHA256 != prev {
			p.add("manifest %d: hash poprzednika nie zgadza się – łańcuch przerwany", "manifest %d: previous hash does not match – chain broken", seq)
		}
		prev = SumHex(data)
		bodies[seq] = m
		if seq == info.Chain.ToSeq && prev != info.Latest.SHA256 {
			p.add("najnowszy manifest nie zgadza się z kotwicą w export.json", "the latest manifest does not match the anchor in export.json")
		}
	}
	if len(chain) != len(bodies) && len(bodies) > 0 {
		p.add("w paczce są manifesty spoza zakresu łańcucha", "the package contains manifests outside the chain range")
	}

	// Segmenty manifestów z zakresu.
	expected := map[string]bool{}
	for _, ref := range info.Manifests {
		m, ok := bodies[ref.Seq]
		if !ok {
			continue
		}
		if SumHex(chain[ref.Seq]) != ref.SHA256 {
			p.add("manifest %d: hash niezgodny z export.json", "manifest %d: hash does not match export.json", ref.Seq)
		}
		c.Manifests++
		for _, s := range m.Segments {
			expected[s.Path] = true
			si, ok := segs[s.Path]
			switch {
			case !ok:
				p.add("brak segmentu %s", "segment %s missing", s.Path)
				continue
			case si.err != nil:
				p.add("segment %s: %v", "segment %s: %v", s.Path, si.err)
			case si.sum != s.SHA256 || si.size != s.Bytes:
				p.add("segment %s: SHA-256 lub rozmiar niezgodny z manifestem – zmieniony", "segment %s: SHA-256 or size does not match the manifest – modified", s.Path)
			case si.records != s.Records:
				p.add("segment %s: %d paczek zamiast %d", "segment %s: %d batches instead of %d", s.Path, si.records, s.Records)
			}
			if si.broken > 0 {
				p.add("segment %s: %d paczek niezgodnych z ich sumą SHA-256", "segment %s: %d batches do not match their SHA-256", s.Path, si.broken)
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
		p.add("segment %s nie należy do żadnego manifestu z zakresu", "segment %s does not belong to any manifest in the range", name)
	}

	// Czytelne zdarzenia (format 2) muszą odpowiadać oryginałom (wybranych agentów).
	var origDigest eventDigest
	for agent, d := range origByAgent {
		if agentSelected(info.Agents, agent) {
			origDigest.merge(*d)
		}
	}
	c.Agents = info.Agents
	c.Events = origDigest.n
	if info.Format != exportFormatV1 && !readDigest.same(origDigest) {
		p.add("czytelne zdarzenia (%d) nie odpowiadają oryginałom (%d) – zdarzenia/ zmienione albo niekompletne", "readable events (%d) do not match the originals (%d) – zdarzenia/ modified or incomplete", readDigest.n, origDigest.n)
	}

	c.Problems = p.result()
	c.OK = len(c.Problems) == 0
	return c
}

const exportReadme = `Vardr – eksport archiwum NIS2 (Urd)
======================================

Paczka zawiera logi w dwóch postaciach: CZYTELNEJ (do analizy w dowolnym
narzędziu) i ORYGINALNEJ (dowód – bajt w bajt to, co przyszło od agentów),
oraz sposób sprawdzenia, że jedno odpowiada drugiemu.

NAJPROŚCIEJ (Windows): uruchom odczytaj.exe w tym folderze (dwuklik).
Program sprawdzi integralność paczki i zapisze w podfolderze ODCZYT:
  RAPORT.txt              wynik sprawdzenia, opis eksportu, zdarzenia
                          wymagające uwagi, statystyki
  zdarzenia\RRRR-MM-DD.txt  wszystkie zdarzenia dnia po kolei, opisane
                          w języku Windows (po polsku albo po angielsku),
                          z danymi zdarzenia
Program nie zmienia paczki. Nie jest podpisany cyfrowo – Windows może
wyświetlić ostrzeżenie („Więcej informacji” → „Uruchom mimo to”). Jeśli
nie uruchamiasz programów z zewnątrz, użyj skryptu w Pythonie (punkt 3).

1. Zdarzenia do odczytu – katalog zdarzenia/
---------------------------------------------
  zdarzenia/RRRR-MM-DD_GG.ndjson.gz
      Jedna linia = jedno zdarzenie (JSON), plik na każdą godzinę
      archiwizacji (UTC), skompresowany gzip. Pola według Elastic Common
      Schema, m.in.:
        @timestamp          czas zdarzenia (UTC)
        host.name           komputer
        event.code          Event ID Windows (np. 4625 – nieudane logowanie)
        event.action        opis czynności, event.outcome – success/failure
        user.name, user.domain, source.ip, process.name, winlog.channel
        agent.id, event.ingested   agent i czas przyjęcia przez serwer
        event.original      PEŁNY oryginalny zapis zdarzenia (XML Windows
                            albo wiadomość syslog z urządzenia)
        log.source.address  adres urządzenia, które wysłało syslog (kolektor)
        vardr.batch_sha256      suma paczki agenta, z której pochodzi zdarzenie
      Odczyt: zcat plik.ndjson.gz | less, jq, 7-Zip; import do Elastic,
      Splunk, OpenSearch, Sentinel itp. jako NDJSON/JSON lines.

  zdarzenia/zdarzenia.csv
      Najważniejsze pola w tabeli dla arkusza kalkulacyjnego (UTF-8,
      separator średnik; najwyżej 1 000 000 wierszy – liczba w export.json).
      Pełny XML zdarzenia jest w plikach NDJSON (kolumna id_zdarzenia).

2. Dowód – oryginały i łańcuch
------------------------------
  segments/   oryginalne segmenty archiwum – paczki agentów w postaci,
              w jakiej przyszły na serwer, przed jakąkolwiek obróbką
  chain/      manifesty godzinowe od pierwszej godziny zakresu do najnowszej;
              każdy zawiera sumy SHA-256 segmentów i SHA-256 poprzedniego
              manifestu (łańcuch – usunięcie lub zmiana danych go przerywa)
  obsluga-niezgodnosci/
              zapis każdej obsługi niezgodności archiwum (np. po przywróceniu
              kopii bazy): kto, kiedy, dlaczego, które pliki przyjęto do spisu
              po sprawdzeniu sum, które odłożono do kwarantanny
  export.json kto, kiedy i w jakim celu zlecił eksport, zakres, liczby,
              kotwica (SHA-256 najnowszego manifestu)
  SHA256SUMS  sumy SHA-256 wszystkich plików paczki

3. Sprawdzenie – bez Vardra
------------------------------
  python3 narzedzia/odczytaj_segmenty.py <ta_paczka.tar>
      (Python 3.8+, tylko biblioteka standardowa) sprawdza:
        - sumy wszystkich plików (SHA256SUMS),
        - ciągłość łańcucha manifestów i kotwicę,
        - każdy segment względem manifestu i każdą paczkę względem jej sumy,
        - że zdarzenia/*.ndjson.gz zawierają DOKŁADNIE te same zdarzenia
          (identyfikatory i oryginalny XML) co oryginalne segmenty.
  python3 narzedzia/odczytaj_segmenty.py <ta_paczka.tar> --wypisz
      wypisuje zdarzenia odczytane wprost z oryginałów (bez części czytelnej).

  Ręcznie: sha256sum -c SHA256SUMS; dalsze kroki jak wyżej.
  SHA-256 najnowszego manifestu (kotwicę) warto porównać z wartością
  zapisaną niezależnie, np. w protokole przekazania lub wydruku z panelu.

Format segmentu: nagłówek "HEIMURD1", potem rekordy: uint32 BE długość
metadanych, metadane JSON (agent, identyfikator paczki, czas przyjęcia,
SHA-256 treści), uint32 BE długość treści, treść – paczka agenta (gzip,
JSON: {"events": [{"id", "source" (kanał), "raw" (XML zdarzenia)}]}).

Eksport ograniczony do wybranych agentów (export.json, pole "agents"):
część czytelna (zdarzenia/, ODCZYT) zawiera tylko ich zdarzenia, a segmenty
(dowód) – wszystkie paczki z wybranych godzin, bo tylko cały segment można
sprawdzić względem manifestu. Sprawdzenie porównuje część czytelną
z oryginałami wybranych agentów.

Zakres eksportu dotyczy godzin archiwizacji (czasu przyjęcia paczek przez
serwer), nie czasu zdarzeń. Pola znormalizowane (host.name, user.name itd.)
wylicza Vardr; rozstrzygający jest zawsze oryginał w event.original.
`

// exportReadmeEn: opis paczki po angielsku (README-EN.txt).
const exportReadmeEn = `Vardr – NIS2 archive export (Urd)
=================================

The package contains the logs in two forms: READABLE (for analysis in any
tool) and ORIGINAL (evidence – byte for byte what came from the agents),
plus a way to check that one matches the other. Directory and file names
are in Polish (they are part of the package format): zdarzenia = events,
narzedzia = tools, obsluga-niezgodnosci = inconsistency handling.

SIMPLEST (Windows): run odczytaj.exe in this folder (double-click).
The program checks the integrity of the package and writes to the ODCZYT
subfolder:
  RAPORT.txt              check result, export description, events that
                          need attention, statistics
  zdarzenia\YYYY-MM-DD.txt  all events of the day in order, described in
                          the language of Windows (Polish or English),
                          with the event data
The program does not modify the package. It is not digitally signed –
Windows may show a warning ("More info" → "Run anyway"). If you do not run
programs from outside, use the Python script (point 3).

1. Events to read – the zdarzenia/ directory
--------------------------------------------
  zdarzenia/YYYY-MM-DD_HH.ndjson.gz
      One line = one event (JSON), one file per archiving hour (UTC),
      gzip-compressed. Fields follow the Elastic Common Schema, including:
        @timestamp          event time (UTC)
        host.name           computer
        event.code          Windows Event ID (e.g. 4625 – failed logon)
        event.action        action description, event.outcome – success/failure
        user.name, user.domain, source.ip, process.name, winlog.channel
        agent.id, event.ingested   agent and time the server accepted it
        event.original      FULL original event record (Windows XML
                            or the syslog message from the device)
        log.source.address  address of the device that sent syslog (collector)
        vardr.batch_sha256  hash of the agent batch the event comes from
      Reading: zcat file.ndjson.gz | less, jq, 7-Zip; import into Elastic,
      Splunk, OpenSearch, Sentinel etc. as NDJSON/JSON lines.

  zdarzenia/zdarzenia.csv
      The most important fields as a table for a spreadsheet (UTF-8,
      semicolon separator; at most 1,000,000 rows – the count is in
      export.json). Column names in the system language at export time.
      The full event XML is in the NDJSON files (event id column).

2. Evidence – originals and the chain
-------------------------------------
  segments/   original archive segments – agent batches as they arrived
              at the server, before any processing
  chain/      hourly manifests from the first hour of the range to the
              latest; each holds SHA-256 hashes of its segments and the
              SHA-256 of the previous manifest (a chain – removing or
              changing data breaks it)
  obsluga-niezgodnosci/
              a record of every archive inconsistency handling (e.g. after
              restoring a database backup): who, when, why, which files were
              accepted into the catalog after checking hashes, which were
              moved to quarantine
  export.json who requested the export, when and why, the range, counts,
              the anchor (SHA-256 of the latest manifest)
  SHA256SUMS  SHA-256 hashes of all files in the package

3. Checking – without Vardr
---------------------------
  python3 narzedzia/odczytaj_segmenty.py <this_package.tar>
      (Python 3.8+, standard library only) checks:
        - hashes of all files (SHA256SUMS),
        - continuity of the manifest chain and the anchor,
        - every segment against its manifest and every batch against its hash,
        - that zdarzenia/*.ndjson.gz contain EXACTLY the same events
          (identifiers and original XML) as the original segments.
  python3 narzedzia/odczytaj_segmenty.py <this_package.tar> --print
      prints the events read directly from the originals (without the
      readable part). Script messages follow the system language
      (VARDR_LANG=en forces English).

  Manually: sha256sum -c SHA256SUMS; further steps as above.
  It is worth comparing the SHA-256 of the latest manifest (the anchor)
  with a value recorded independently, e.g. in a handover protocol or
  a printout from the panel.

Segment format: header "HEIMURD1", then records: uint32 BE metadata
length, JSON metadata (agent, batch identifier, time accepted, SHA-256 of
the content), uint32 BE content length, content – the agent batch (gzip,
JSON: {"events": [{"id", "source" (channel), "raw" (event XML)}]}).

An export limited to selected agents (export.json, field "agents"): the
readable part (zdarzenia/, ODCZYT) contains only their events, while the
segments (evidence) contain all batches from the selected hours, because
only a whole segment can be checked against its manifest. The check
compares the readable part with the originals of the selected agents.

The export range refers to archiving hours (when the server accepted the
batches), not event time. Normalized fields (host.name, user.name etc.)
are computed by Vardr; the original in event.original is always decisive.
`
