// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/internal/lang"
)

// Uzgodnienie spisu z dyskiem – obsługa niezgodności „plik nie występuje
// w spisie archiwum”. Typowa przyczyna: przywrócenie kopii bazy Saga –
// spis wraca do chwili zrzutu, a segmenty i manifesty zapisane później
// zostają na dysku bez wpisu.
//
// Nic nie jest usuwane ani przepisywane:
//   - manifest z dysku, który przedłuża łańcuch (numer, godzina i hash
//     poprzednika zgodne z końcem spisu, sumy jego segmentów zgodne), wraca
//     do spisu bez zmian – łańcuch dowodzi, że to ten sam zapis;
//   - segment bez manifestu, którego format i sumy wszystkich paczek są
//     poprawne, wraca do spisu jako otwarty i trafia do najbliższego
//     manifestu (jak segment zatwierdzony po zamknięciu godziny);
//   - plik odrzucony zostaje tam, gdzie był (weryfikacja nadal go zgłasza),
//     albo – decyzją administratora – trafia do kwarantanny (Quarantine).
//
// Automatycznie (po przywróceniu kopii) przyjmowane są tylko pliki
// utworzone w oknie czasu od zrzutu bazy do przywrócenia; resztę rozstrzyga
// administrator w panelu (z powodem, w audycie). Każda operacja zostawia
// wpis w spisie (urd.recoveries) i plik w katalogu recoveries/.

// ReconcileOptions ogranicza uzgodnienie.
type ReconcileOptions struct {
	// From–To: okno czasu utworzenia plików (zrzut bazy → przywrócenie);
	// zero – bez ograniczenia (decyzja administratora).
	From, To time.Time
	// Only: tylko te pliki (ścieżki względne); puste – wszystkie nieznane.
	Only []string
}

// ReconciledManifest to manifest przywrócony do spisu.
type ReconciledManifest struct {
	Seq      int64     `json:"seq"`
	Hour     time.Time `json:"hour"`
	Path     string    `json:"path"`
	Segments int       `json:"segments"`
	Records  int64     `json:"records"`
}

// Rejected to plik, którego nie przyjęto (z powodem).
type Rejected struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ReconcileResult to wynik uzgodnienia albo kwarantanny.
type ReconcileResult struct {
	Manifests   []ReconciledManifest `json:"manifests"`
	Segments    []Segment            `json:"segments"`
	Quarantined []string             `json:"quarantined"`
	Rejected    []Rejected           `json:"rejected"`
}

// Summary opisuje wynik jednym zdaniem (dziennik, panel) w języku l.
func (r ReconcileResult) Summary(l string) string {
	var parts []string
	if n := len(r.Manifests); n > 0 {
		parts = append(parts, fmt.Sprintf(lang.Pick(l, "przywrócone manifesty: %d", "manifests restored: %d"), n))
	}
	if n := len(r.Segments); n > 0 {
		parts = append(parts, fmt.Sprintf(lang.Pick(l, "przyjęte segmenty: %d", "segments accepted: %d"), n))
	}
	if n := len(r.Quarantined); n > 0 {
		parts = append(parts, fmt.Sprintf(lang.Pick(l, "w kwarantannie: %d", "quarantined: %d"), n))
	}
	if n := len(r.Rejected); n > 0 {
		parts = append(parts, fmt.Sprintf(lang.Pick(l, "odrzucone: %d", "rejected: %d"), n))
	}
	if len(parts) == 0 {
		return lang.Pick(l, "brak plików do uzgodnienia", "no files to reconcile")
	}
	return strings.Join(parts, ", ")
}

var (
	segNameRe = regexp.MustCompile(`^segments/\d{4}/\d{2}/\d{2}/\d{2}/seg-(\d{1,19})\.urd$`)
	manNameRe = regexp.MustCompile(`^manifests/(\d{4}/\d{2}/\d{2}/\d{2})\.json$`)
)

// segmentTimes odczytuje godzinę i czas utworzenia z kanonicznej ścieżki segmentu.
func segmentTimes(p string) (hour, created time.Time, ok bool) {
	m := segNameRe.FindStringSubmatch(p)
	if m == nil {
		return hour, created, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return hour, created, false
	}
	created = time.Unix(0, n).UTC()
	hour = created.Truncate(time.Hour)
	return hour, created, SegmentPath(hour, created) == p
}

func manifestHour(p string) (time.Time, bool) {
	m := manNameRe.FindStringSubmatch(p)
	if m == nil {
		return time.Time{}, false
	}
	h, err := time.Parse("2006/01/02/15", m[1])
	return h.UTC(), err == nil
}

// ValidUnknownPath: ścieżka nieznanego pliku archiwum w kanonicznej postaci
// (segment albo manifest) – tylko takie pliki można przyjąć albo odłożyć.
func ValidUnknownPath(p string) bool {
	if _, _, ok := segmentTimes(p); ok {
		return true
	}
	_, ok := manifestHour(p)
	return ok
}

// inWindow: czy chwila mieści się w oknie (zero – bez ograniczeń).
func (o ReconcileOptions) inWindow(t time.Time) bool {
	if !o.From.IsZero() && t.Before(o.From) {
		return false
	}
	if !o.To.IsZero() && t.After(o.To) {
		return false
	}
	return true
}

// unknownFiles zwraca pliki na dysku nieznane spisowi oraz bieżący stan spisu.
func (a *Archive) unknownFiles(ctx context.Context) (unknown []string, open map[string]Segment, err error) {
	onDisk, err := a.listFiles()
	if err != nil {
		return nil, nil, err
	}
	ms, err := a.Cat.Manifests(ctx)
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, m := range ms {
		known[ManifestPath(m.Hour)] = true
		if m.Body == nil {
			continue
		}
		var body Manifest
		if err := json.Unmarshal(m.Body, &body); err != nil {
			return nil, nil, fmt.Errorf("manifest %d: %w", m.Seq, err)
		}
		for _, s := range body.Segments {
			known[s.Path] = true
		}
	}
	segs, err := a.Cat.OpenSegments(ctx)
	if err != nil {
		return nil, nil, err
	}
	open = map[string]Segment{}
	for _, s := range segs {
		known[s.Path] = true
		open[s.Path] = s
	}
	for _, f := range onDisk {
		if !known[f] {
			unknown = append(unknown, f)
		}
	}
	sort.Strings(unknown)
	return unknown, open, nil
}

// readSegment czyta segment w całości: format, sumy paczek, SHA-256 pliku.
func (a *Archive) readSegment(p string) (Segment, error) {
	hour, created, ok := segmentTimes(p)
	if !ok {
		return Segment{}, lang.Errorf("nazwa pliku nie jest nazwą segmentu archiwizatora", "the file name is not an archiver segment name")
	}
	s := Segment{Path: p, Hour: hour, CreatedAt: created}
	f, err := os.Open(a.abs(p))
	if err != nil {
		return s, err
	}
	defer f.Close()
	h := sha256.New()
	cr := &countingReader{r: io.TeeReader(f, h)}
	r, err := NewReader(cr)
	if err != nil {
		return s, err
	}
	for {
		meta, payload, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s, lang.Errorf("paczka %d: %w", "batch %d: %w", s.Records+1, err)
		}
		if SumHex(payload) != meta.SHA256 || len(payload) != meta.Bytes {
			return s, lang.Errorf("paczka %d niezgodna z jej sumą SHA-256", "batch %d does not match its SHA-256", s.Records+1)
		}
		s.Records++
		at := meta.ReceivedAt.UTC()
		if s.FirstReceivedAt.IsZero() || at.Before(s.FirstReceivedAt) {
			s.FirstReceivedAt = at
		}
		if at.After(s.LastReceivedAt) {
			s.LastReceivedAt = at
		}
	}
	if _, err := io.Copy(io.Discard, cr); err != nil {
		return s, err
	}
	s.Bytes = cr.n
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	return s, nil
}

// Reconcile przyjmuje do spisu pliki z dysku, które spisowi umknęły
// (zasady w komentarzu na początku pliku). Nie może działać równolegle
// z Seal ani Expire – archiwizator woła ją przy starcie (po przywróceniu)
// albo w pętli obsługi, poza zamykaniem godzin.
func (a *Archive) Reconcile(ctx context.Context, opt ReconcileOptions) (ReconcileResult, error) {
	res := ReconcileResult{Manifests: []ReconciledManifest{}, Segments: []Segment{}, Quarantined: []string{}, Rejected: []Rejected{}}
	unknown, open, err := a.unknownFiles(ctx)
	if err != nil {
		return res, err
	}
	want := func(p string) bool { return len(opt.Only) == 0 || slices.Contains(opt.Only, p) }
	for _, p := range opt.Only {
		if !slices.Contains(unknown, p) {
			res.Rejected = append(res.Rejected, Rejected{p, a.tr("plik nie jest (już) nieznany spisowi albo go nie ma", "the file is not (or no longer) unknown to the catalog, or it is gone")})
		}
	}
	isUnknown := map[string]bool{}
	for _, p := range unknown {
		isUnknown[p] = true
	}

	// 1. Manifesty przedłużające łańcuch, godzina po godzinie.
	inManifest := map[string]string{} // segment → nieprzyjęty manifest, który go zawiera
	last, hasLast, err := a.Cat.LastManifest(ctx)
	if err != nil {
		return res, err
	}
	var diskManifests []string
	for _, p := range unknown {
		if _, ok := manifestHour(p); ok {
			diskManifests = append(diskManifests, p)
		}
	}
	sort.Strings(diskManifests) // ścieżki RRRR/MM/DD/GG – kolejność godzin
	accepted := map[string]bool{}
	for _, mp := range diskManifests {
		hour, _ := manifestHour(mp)
		body, rec, segs, reason := a.checkDiskManifest(mp, hour, last, hasLast, open, isUnknown)
		if reason == "" && !want(mp) {
			reason = a.tr("nie wskazano", "not selected")
		}
		if reason == "" && !opt.inWindow(body.CreatedAt) {
			reason = fmt.Sprintf(a.tr("utworzony %s – poza oknem przywrócenia", "created %s – outside the restore window"), body.CreatedAt.Format(time.RFC3339))
		}
		if reason != "" {
			for _, s := range body.Segments {
				inManifest[s.Path] = mp
			}
			if want(mp) {
				res.Rejected = append(res.Rejected, Rejected{mp, reason})
			}
			continue
		}
		var paths []string
		for _, s := range segs {
			if _, ok := open[s.Path]; !ok {
				if err := a.Cat.AddSegment(ctx, s); err != nil {
					return res, fmt.Errorf("registering segment %s: %w", s.Path, err)
				}
			}
			paths = append(paths, s.Path)
			accepted[s.Path] = true
		}
		if err := a.Cat.AddManifest(ctx, rec, paths); err != nil {
			return res, fmt.Errorf("restoring manifest %s: %w", mp, err)
		}
		res.Manifests = append(res.Manifests, ReconciledManifest{Seq: rec.Seq, Hour: rec.Hour, Path: mp, Segments: rec.Segments,
			Records: rec.Records})
		last, hasLast = rec, true
	}

	// 2. Segmenty bez manifestu.
	for _, p := range unknown {
		if accepted[p] || !want(p) {
			continue
		}
		if _, ok := manifestHour(p); ok {
			continue
		}
		_, created, ok := segmentTimes(p)
		switch {
		case !ok:
			res.Rejected = append(res.Rejected, Rejected{p, a.tr("nazwa pliku nie jest nazwą segmentu archiwizatora", "the file name is not an archiver segment name")})
			continue
		case inManifest[p] != "":
			res.Rejected = append(res.Rejected, Rejected{p, fmt.Sprintf(a.tr("należy do manifestu %s, którego nie przyjęto", "belongs to manifest %s, which was not accepted"), inManifest[p])})
			continue
		case !opt.inWindow(created):
			res.Rejected = append(res.Rejected, Rejected{p, fmt.Sprintf(a.tr("utworzony %s – poza oknem przywrócenia", "created %s – outside the restore window"),
				created.Format(time.RFC3339))})
			continue
		}
		s, err := a.readSegment(p)
		if err != nil {
			res.Rejected = append(res.Rejected, Rejected{p, a.tr("uszkodzony: ", "damaged: ") + a.msg(err)})
			continue
		}
		s.RegisteredAt = a.now()
		if err := a.Cat.AddSegment(ctx, s); err != nil {
			return res, fmt.Errorf("registering segment %s: %w", p, err)
		}
		res.Segments = append(res.Segments, s)
	}
	return res, nil
}

// checkDiskManifest sprawdza, czy manifest z dysku przedłuża łańcuch spisu
// i czy jego segmenty są zgodne z zapisem. Pusty powód = można przyjąć.
func (a *Archive) checkDiskManifest(mp string, hour time.Time, last ManifestRecord, hasLast bool, open map[string]Segment,
	unknown map[string]bool) (Manifest, ManifestRecord, []Segment, string) {
	var body Manifest
	data, err := os.ReadFile(a.abs(mp))
	if err != nil {
		return body, ManifestRecord{}, nil, err.Error()
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return body, ManifestRecord{}, nil, a.tr("nieczytelna treść: ", "unreadable content: ") + err.Error()
	}
	wantSeq, wantPrev := int64(1), GenesisPrev
	if hasLast {
		wantSeq, wantPrev = last.Seq+1, last.SHA256
	}
	switch {
	case body.Format != ManifestFormat:
		return body, ManifestRecord{}, nil, a.tr("nieznany format manifestu", "unknown manifest format")
	case !body.Hour.Equal(hour):
		return body, ManifestRecord{}, nil, a.tr("godzina w treści różni się od nazwy pliku", "the hour in the content differs from the file name")
	case body.Seq != wantSeq || body.PrevSHA256 != wantPrev:
		return body, ManifestRecord{}, nil, fmt.Sprintf(a.tr("nie przedłuża łańcucha (numer %d, oczekiwany %d z hashem poprzednika końca spisu)",
			"does not extend the chain (number %d, expected %d with the previous hash of the catalog end)"),
			body.Seq, wantSeq)
	case hasLast && !hour.Equal(last.Hour.UTC().Add(time.Hour)):
		return body, ManifestRecord{}, nil, a.tr("nie jest kolejną godziną po końcu spisu", "is not the next hour after the catalog end")
	}
	var segs []Segment
	for _, s := range body.Segments {
		if o, ok := open[s.Path]; ok {
			if o.SHA256 != s.SHA256 || o.Bytes != s.Bytes || o.Records != s.Records {
				return body, ManifestRecord{}, nil, fmt.Sprintf(a.tr("segment %s różni się od wpisu w spisie", "segment %s differs from the catalog entry"), s.Path)
			}
			segs = append(segs, o)
			continue
		}
		if !unknown[s.Path] {
			return body, ManifestRecord{}, nil, fmt.Sprintf(a.tr("segment %s brakuje albo należy już do innego manifestu", "segment %s is missing or already belongs to another manifest"), s.Path)
		}
		got, err := a.readSegment(s.Path)
		if err != nil {
			return body, ManifestRecord{}, nil, "segment " + s.Path + ": " + a.msg(err)
		}
		if got.SHA256 != s.SHA256 || got.Bytes != s.Bytes || got.Records != s.Records {
			return body, ManifestRecord{}, nil, fmt.Sprintf(a.tr("segment %s niezgodny z manifestem", "segment %s does not match the manifest"), s.Path)
		}
		got.FirstReceivedAt, got.LastReceivedAt = s.FirstReceivedAt, s.LastReceivedAt
		segs = append(segs, got)
	}
	var recs, size int64
	for _, s := range body.Segments {
		recs += int64(s.Records)
		size += s.Bytes
	}
	if recs != body.Records || size != body.Bytes {
		return body, ManifestRecord{}, nil, a.tr("sumy manifestu nie zgadzają się z listą segmentów", "manifest totals do not match the segment list")
	}
	rec := ManifestRecord{Seq: body.Seq, Hour: hour, SHA256: SumHex(data), PrevSHA256: body.PrevSHA256, Segments: len(body.Segments),
		Records: body.Records, Bytes: body.Bytes, CreatedAt: body.CreatedAt.UTC(), Body: data}
	return body, rec, segs, ""
}

// QuarantineDir: katalog kwarantanny w archiwum (poza segments/ i
// manifests/, więc weryfikacja go nie zgłasza; pliki zostają zachowane).
const QuarantineDir = "quarantine"

// Quarantine odkłada wskazane pliki nieznane spisowi do kwarantanny
// (quarantine/<czas>/<ścieżka>, tylko do odczytu). Plików znanych spisowi
// nie rusza.
func (a *Archive) Quarantine(ctx context.Context, paths []string) (ReconcileResult, error) {
	res := ReconcileResult{Manifests: []ReconciledManifest{}, Segments: []Segment{}, Quarantined: []string{}, Rejected: []Rejected{}}
	unknown, _, err := a.unknownFiles(ctx)
	if err != nil {
		return res, err
	}
	stamp := a.now().Format("20060102-150405")
	for _, p := range paths {
		if !ValidUnknownPath(p) || !slices.Contains(unknown, p) {
			res.Rejected = append(res.Rejected, Rejected{p, a.tr("plik nie jest (już) nieznany spisowi albo go nie ma", "the file is not (or no longer) unknown to the catalog, or it is gone")})
			continue
		}
		dst := path.Join(QuarantineDir, stamp, p)
		full := a.abs(dst)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return res, err
		}
		if err := os.Rename(a.abs(p), full); err != nil {
			res.Rejected = append(res.Rejected, Rejected{p, err.Error()})
			continue
		}
		syncDir(filepath.Dir(full))
		removeEmptyDirs(a.Dir, path.Dir(p))
		res.Quarantined = append(res.Quarantined, dst)
	}
	return res, nil
}

// RecoveryLogDir: zapis operacji uzgodnienia w katalogu archiwum – dowód
// przetrwa kolejne przywrócenie bazy (wpis w urd.recoveries by zniknął).
const RecoveryLogDir = "recoveries"

// LogRecovery zapisuje operację jako plik JSON tylko do odczytu.
func (a *Archive) LogRecovery(r Recovery) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s-%d.json", a.now().Format("20060102-150405"), r.Kind, r.ID)
	full := filepath.Join(a.Dir, RecoveryLogDir, name)
	if _, err := os.Stat(full); err == nil {
		return nil
	}
	return writeFileAtomic(full, append(data, '\n'))
}

// Recovery to operacja uzgodnienia spisu z dyskiem (urd.recoveries).
type Recovery struct {
	ID             int64            `json:"id"`
	Kind           string           `json:"kind"` // restore | adopt | quarantine
	RequestedBy    string           `json:"requested_by"`
	RequestedAt    time.Time        `json:"requested_at"`
	Reason         string           `json:"reason"`
	Paths          []string         `json:"paths"`
	Backup         string           `json:"backup,omitempty"`
	WindowFrom     *time.Time       `json:"window_from,omitempty"`
	WindowTo       *time.Time       `json:"window_to,omitempty"`
	VerificationID *int64           `json:"verification_id,omitempty"`
	ProcessedAt    *time.Time       `json:"processed_at,omitempty"`
	OK             *bool            `json:"ok,omitempty"`
	Result         *ReconcileResult `json:"result,omitempty"`
	Error          string           `json:"error,omitempty"`
}

// Run wykonuje operację na archiwum (bez zapisu wyniku).
func (a *Archive) Run(ctx context.Context, r Recovery) (ReconcileResult, error) {
	switch r.Kind {
	case "restore":
		if r.WindowFrom == nil || r.WindowTo == nil {
			return ReconcileResult{}, lang.Errorf("brak okna czasu przywrócenia (czasu zrzutu bazy) – pliki rozstrzygnie administrator w panelu",
				"no restore time window (database dump time) – an administrator will decide on the files in the panel")
		}
		return a.Reconcile(ctx, ReconcileOptions{From: *r.WindowFrom, To: *r.WindowTo})
	case "adopt":
		if len(r.Paths) == 0 {
			return ReconcileResult{}, lang.Errorf("brak wskazanych plików", "no files selected")
		}
		return a.Reconcile(ctx, ReconcileOptions{Only: r.Paths})
	case "quarantine":
		if len(r.Paths) == 0 {
			return ReconcileResult{}, lang.Errorf("brak wskazanych plików", "no files selected")
		}
		return a.Quarantine(ctx, r.Paths)
	}
	return ReconcileResult{}, fmt.Errorf("unknown operation kind %q", r.Kind)
}
