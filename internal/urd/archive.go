package urd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Archive to katalog archiwum na dysku razem z jego spisem.
type Archive struct {
	Dir string
	Cat Catalog
	Now func() time.Time
}

// New tworzy archiwum (katalog musi istnieć i być zapisywalny).
func New(dir string, cat Catalog) *Archive {
	return &Archive{Dir: dir, Cat: cat, Now: time.Now}
}

func (a *Archive) now() time.Time { return a.Now().UTC() }

func (a *Archive) abs(rel string) string { return filepath.Join(a.Dir, filepath.FromSlash(rel)) }

// SegmentWriter zapisuje otwarty segment. Plik ma rozszerzenie .tmp do
// zatwierdzenia – po awarii taki plik jest usuwany, a niepotwierdzone
// wiadomości wracają z kolejki.
type SegmentWriter struct {
	a           *Archive
	seg         Segment
	f           *os.File
	h           hash.Hash
	w           *bufio.Writer
	first, last time.Time
}

// OpenSegment zakłada nowy segment w bieżącej godzinie.
func (a *Archive) OpenSegment() (*SegmentWriter, error) {
	now := a.now()
	seg := Segment{Hour: now.Truncate(time.Hour), CreatedAt: now}
	seg.Path = SegmentPath(seg.Hour, now)
	full := a.abs(seg.Path)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(full+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	s := &SegmentWriter{a: a, seg: seg, f: f, h: sha256.New()}
	s.w = bufio.NewWriterSize(io.MultiWriter(f, s.h), 256<<10)
	if _, err := s.w.WriteString(Magic); err != nil {
		s.Abort()
		return nil, err
	}
	s.seg.Bytes = int64(len(Magic))
	return s, nil
}

// Add dopisuje paczkę.
func (s *SegmentWriter) Add(meta RecordMeta, payload []byte) error {
	n, err := WriteRecord(s.w, meta, payload)
	s.seg.Bytes += n
	if err != nil {
		return err
	}
	s.seg.Records++
	if s.seg.FirstReceivedAt.IsZero() || meta.ReceivedAt.Before(s.seg.FirstReceivedAt) {
		s.seg.FirstReceivedAt = meta.ReceivedAt.UTC()
	}
	if meta.ReceivedAt.After(s.seg.LastReceivedAt) {
		s.seg.LastReceivedAt = meta.ReceivedAt.UTC()
	}
	return nil
}

func (s *SegmentWriter) Bytes() int64                    { return s.seg.Bytes }
func (s *SegmentWriter) Records() int                    { return s.seg.Records }
func (s *SegmentWriter) Hour() time.Time                 { return s.seg.Hour }
func (s *SegmentWriter) CreatedAt() time.Time            { return s.seg.CreatedAt }
func (s *SegmentWriter) Path() string                    { return s.seg.Path }
func (s *SegmentWriter) Age(now time.Time) time.Duration { return now.Sub(s.seg.CreatedAt) }

// Commit zapisuje segment trwale (fsync, zmiana nazwy, tylko do odczytu)
// i rejestruje go w spisie. Dopiero potem wolno potwierdzić wiadomości.
func (s *SegmentWriter) Commit(ctx context.Context) (Segment, error) {
	full := s.a.abs(s.seg.Path)
	err := s.w.Flush()
	if err == nil {
		err = s.f.Sync()
	}
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(full+".tmp", full)
	}
	if err != nil {
		_ = os.Remove(full + ".tmp")
		return s.seg, err
	}
	_ = os.Chmod(full, 0o440)
	syncDir(filepath.Dir(full))
	s.seg.SHA256 = hex.EncodeToString(s.h.Sum(nil))
	if err := s.a.Cat.AddSegment(ctx, s.seg); err != nil {
		removeFile(full)
		return s.seg, fmt.Errorf("rejestracja segmentu: %w", err)
	}
	return s.seg, nil
}

// Abort porzuca segment (wiadomości nie były potwierdzone).
func (s *SegmentWriter) Abort() {
	_ = s.f.Close()
	_ = os.Remove(s.a.abs(s.seg.Path) + ".tmp")
}

// CleanTemp usuwa pozostałości po przerwanej pracy (*.tmp).
func (a *Archive) CleanTemp() (int, error) {
	n := 0
	err := filepath.WalkDir(a.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".tmp") {
			if err := os.Remove(p); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// Seal tworzy manifesty dla wszystkich zakończonych godzin (przed bieżącą)
// i zwraca ich liczbę. Każda godzina dostaje manifest, także pusta.
// Segment zatwierdzony po zamknięciu swojej godziny (np. po awarii) trafia
// do najbliższego manifestu.
func (a *Archive) Seal(ctx context.Context) (int, error) {
	now := a.now()
	current := now.Truncate(time.Hour)
	last, ok, err := a.Cat.LastManifest(ctx)
	if err != nil {
		return 0, err
	}
	open, err := a.Cat.OpenSegments(ctx)
	if err != nil {
		return 0, err
	}
	prev, seq, start := GenesisPrev, int64(1), time.Time{}
	if ok {
		prev, seq, start = last.SHA256, last.Seq+1, last.Hour.UTC().Add(time.Hour)
	} else {
		if len(open) == 0 {
			return 0, nil
		}
		start = open[0].Hour.UTC()
		for _, s := range open {
			if s.Hour.Before(start) {
				start = s.Hour.UTC()
			}
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].CreatedAt.Before(open[j].CreatedAt) })

	n := 0
	for h := start; h.Before(current); h = h.Add(time.Hour) {
		var segs []Segment
		var paths []string
		rest := open[:0]
		for _, s := range open {
			if !s.Hour.After(h) {
				segs = append(segs, s)
				paths = append(paths, s.Path)
			} else {
				rest = append(rest, s)
			}
		}
		open = rest
		m := NewManifest(seq, h, prev, segs, now)
		body, err := m.Encode()
		if err != nil {
			return n, err
		}
		sum := SumHex(body)
		if err := writeFileAtomic(a.abs(ManifestPath(h)), body); err != nil {
			return n, err
		}
		rec := ManifestRecord{Seq: seq, Hour: h, SHA256: sum, PrevSHA256: prev, Segments: len(segs),
			Records: m.Records, Bytes: m.Bytes, CreatedAt: m.CreatedAt, Body: body}
		if err := a.Cat.AddManifest(ctx, rec, paths); err != nil {
			removeFile(a.abs(ManifestPath(h)))
			return n, fmt.Errorf("zapis manifestu %s: %w", h.Format(time.RFC3339), err)
		}
		prev, seq = sum, seq+1
		n++
	}
	return n, nil
}

// Expire usuwa dane godzin starszych niż retencja. Wpisy manifestów
// zostają w spisie (oznaczone jako wygasłe), więc łańcuch pozostaje ciągły.
func (a *Archive) Expire(ctx context.Context, retention time.Duration) (int, error) {
	cutoff := a.now().Add(-retention)
	ms, err := a.Cat.Manifests(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range ms {
		if m.ExpiredAt != nil || m.Hour.Add(time.Hour).After(cutoff) {
			continue
		}
		var body Manifest
		if err := json.Unmarshal(m.Body, &body); err != nil {
			return n, fmt.Errorf("manifest %d: %w", m.Seq, err)
		}
		for _, s := range body.Segments {
			removeFile(a.abs(s.Path))
			removeEmptyDirs(a.Dir, path.Dir(s.Path))
		}
		removeFile(a.abs(ManifestPath(m.Hour)))
		removeEmptyDirs(a.Dir, path.Dir(ManifestPath(m.Hour)))
		if err := a.Cat.ExpireManifest(ctx, m.Seq, a.now()); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeFileAtomic zapisuje plik tylko do odczytu (tmp + fsync + rename).
func writeFileAtomic(full string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(full); err == nil {
		return fmt.Errorf("plik %s już istnieje", full)
	}
	tmp := full + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, full)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(full, 0o440)
	syncDir(filepath.Dir(full))
	return nil
}

// removeFile usuwa plik tylko do odczytu (Windows wymaga zdjęcia atrybutu).
func removeFile(full string) {
	_ = os.Chmod(full, 0o640)
	_ = os.Remove(full)
}

// removeEmptyDirs usuwa puste katalogi od rel w górę (bez katalogu głównego).
func removeEmptyDirs(root, rel string) {
	for rel != "." && rel != "/" && rel != "" {
		if os.Remove(filepath.Join(root, filepath.FromSlash(rel))) != nil {
			return
		}
		rel = path.Dir(rel)
	}
}

// syncDir utrwala wpis katalogu po zmianie nazwy (na Windows bez znaczenia).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// MarkerFile oznacza katalog archiwum. Chroni przed pracą na pustym
// katalogu, gdy dysk archiwum nie został zamontowany (wpis nofail w fstab).
const MarkerFile = ".urd-archive"

// ErrWrongDir: spis ma manifesty, a katalog nie wygląda na archiwum.
var ErrWrongDir = errors.New("katalog nie zawiera archiwum, choć spis w bazie ma manifesty – dysk archiwum niezamontowany?")

// CheckDir sprawdza, czy katalog jest archiwum ze spisu, i zakłada znacznik
// w nowym archiwum (albo w archiwum sprzed wprowadzenia znacznika).
func (a *Archive) CheckDir(ctx context.Context) error {
	marker := filepath.Join(a.Dir, MarkerFile)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	_, hasManifests, err := a.Cat.LastManifest(ctx)
	if err != nil {
		return err
	}
	if hasManifests {
		if _, err := os.Stat(filepath.Join(a.Dir, "manifests")); err != nil {
			return ErrWrongDir
		}
	}
	return os.WriteFile(marker, []byte("Heimdall – archiwum NIS2 (Urd). Nie usuwać.\n"), 0o440)
}
