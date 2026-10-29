// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logfile to źródło agenta Linux czytające dowolne pliki logów
// wiersz po wierszu (sekcja files: konfiguracji). Wiersz trafia na serwer
// jako wiadomość syslog RFC 5424 (źródło „syslog:file”) z nazwą hosta agenta
// i nazwą programu z konfiguracji, więc rozbierają go dekodery dopasowane po
// app – tak jak wiadomości wysyłane przez rsyslog; bez dekodera zdarzenie
// ma zbiór syslog.generic. Czas zdarzenia to chwila odczytu (dekoder może
// wziąć czas z treści).
//
// Każdy plik to osobny kanał („file:/var/log/app.log”). Rotacja przez zmianę
// nazwy (logrotate: app.log → app.log.1) i przez obcięcie (copytruncate):
// agent doczytuje stary plik do końca i zaczyna nowy od początku. Pozycja
// (numer rekordu) to generacja pliku w górnych bitach – rośnie przy każdej
// rotacji – i przesunięcie za wierszem w dolnych 40 bitach, więc
// identyfikatory zdarzeń się nie powtarzają, a po restarcie odczyt wznawia
// się za ostatnim wysłanym wierszem. Plik krótszy niż zapisana pozycja to
// nowy plik po rotacji – czytany od początku.
package logfile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"siem/agent/internal/source"
)

// SourceName: źródło zdarzeń w paczce (ścieżka syslog na serwerze).
const SourceName = "syslog:file"

const (
	offsetBits = 40
	offsetMask = 1<<offsetBits - 1
	maxLine    = 64 << 10 // dłuższe wiersze są przycinane
)

// Source czyta jeden plik logu.
type Source struct {
	Path   string
	App    string        // nazwa programu w nagłówku (domyślnie AppName(Path))
	Host   string        // nazwa hosta w nagłówku
	Oldest bool          // start_at: oldest – cały plik przy pierwszym uruchomieniu
	Poll   time.Duration // domyślnie 500 ms
	Log    *slog.Logger
}

// Expand rozwija wzorce ścieżek w listę plików (bez powtórzeń i bez plików
// w katalogu skip – log i stan agenta). Ścieżka bez znaków wzorca zostaje,
// nawet gdy pliku jeszcze nie ma (źródło na niego czeka).
func Expand(paths []string, skip string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		var list []string
		if strings.ContainsAny(p, "*?[") {
			list, _ = filepath.Glob(p)
		} else {
			list = []string{p}
		}
		for _, f := range list {
			f = filepath.Clean(f)
			if seen[f] || (skip != "" && strings.HasPrefix(f, filepath.Clean(skip)+string(filepath.Separator))) {
				continue
			}
			if fi, err := os.Stat(f); err == nil && fi.IsDir() {
				continue
			}
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// AppName: domyślna nazwa programu – nazwa pliku bez rozszerzenia.
func AppName(path string) string {
	b := filepath.Base(path)
	if i := strings.IndexByte(b, '.'); i > 0 {
		b = b[:i]
	}
	return b
}

func (s *Source) Channel() string { return "file:" + s.Path }

func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	// Brak pliku nie jest błędem kanału – program może go jeszcze nie utworzyć.
	for waited := false; ; waited = true {
		if _, err := os.Stat(s.Path); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return start, err
		}
		if !waited && s.Log != nil {
			s.Log.Info("files: no log file yet – waiting", "path", s.Path)
		}
		select {
		case <-ctx.Done():
			return start, ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	t := &tailer{src: s, out: out, pos: start}
	fi, err := os.Stat(s.Path)
	if err != nil {
		return start, err
	}
	var off int64
	switch {
	case start.Valid:
		t.gen = start.RecordID >> offsetBits
		off = int64(start.RecordID & offsetMask)
		if off > fi.Size() {
			t.gen, off = t.gen+1, 0 // nowy plik po rotacji
		}
	case start.Oldest || s.Oldest:
	default:
		off = fi.Size()
	}
	err = t.follow(ctx, off)
	return t.pos, err
}

type tailer struct {
	src *Source
	out chan<- source.Record
	pos source.Position
	gen uint64
}

func (t *tailer) follow(ctx context.Context, off int64) error {
	poll := t.src.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	var f *os.File
	var fi os.FileInfo
	var partial []byte
	open := func(at int64) error {
		nf, err := os.Open(t.src.Path)
		if err != nil {
			return err
		}
		st, err := nf.Stat()
		if err == nil {
			_, err = nf.Seek(at, io.SeekStart)
		}
		if err != nil {
			nf.Close()
			return err
		}
		if f != nil {
			f.Close()
		}
		f, fi, off, partial = nf, st, at, nil
		return nil
	}
	if err := open(off); err != nil {
		return err
	}
	defer func() { f.Close() }()
	// lines wysyła pełne wiersze z partial; flush – także resztę bez końca wiersza.
	lines := func(flush bool) bool {
		for {
			i := bytes.IndexByte(partial, '\n')
			if i < 0 {
				if flush && len(partial) > 0 {
					rest := partial
					partial = nil
					return t.emit(ctx, rest, off)
				}
				return true
			}
			line := partial[:i]
			partial = partial[i+1:]
			if !t.emit(ctx, line, off-int64(len(partial))) {
				return false
			}
		}
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			off += int64(n)
			partial = append(partial, buf[:n]...)
			if !lines(false) {
				return ctx.Err()
			}
			if len(partial) > maxLine {
				// Wiersz bez końca dłuższy niż limit – wysłany przycięty.
				if !t.emit(ctx, partial, off) {
					return ctx.Err()
				}
				partial = nil
			}
			continue
		}
		if err != nil && err != io.EOF {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
		st, err := os.Stat(t.src.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue // rotacja w toku
		case err != nil:
			return err
		case !os.SameFile(st, fi):
			// Nowy plik pod ścieżką: dokończ stary, potem nowy od początku.
			if rest, _ := io.ReadAll(f); len(rest) > 0 {
				off += int64(len(rest))
				partial = append(partial, rest...)
			}
			if !lines(true) {
				return ctx.Err()
			}
			t.gen++
			if err := open(0); err != nil {
				return err
			}
		case st.Size() < off:
			// Obcięty (copytruncate): pozostałość bez końca wiersza i od początku.
			if !lines(true) {
				return ctx.Err()
			}
			t.gen++
			if err := open(0); err != nil {
				return err
			}
		}
	}
}

// emit wysyła wiersz kończący się na przesunięciu end. false – ctx zakończony.
func (t *tailer) emit(ctx context.Context, line []byte, end int64) bool {
	text := strings.TrimRight(string(line), "\r\n")
	if strings.TrimSpace(text) == "" {
		return true
	}
	rec := t.src.Record(text, t.gen<<offsetBits|uint64(end)&offsetMask, time.Now().UTC())
	select {
	case t.out <- rec:
		t.pos = source.Position{RecordID: rec.RecordID, Valid: true}
		return true
	case <-ctx.Done():
		return false
	}
}

// Record buduje rekord z wiersza: syslog RFC 5424, facility user, severity info.
func (s *Source) Record(line string, rid uint64, at time.Time) source.Record {
	size := len(line)
	truncated := size > maxLine
	if truncated {
		line = line[:maxLine]
	}
	line = strings.ToValidUTF8(line, "�")
	app := s.App
	if app == "" {
		app = AppName(s.Path)
	}
	raw := fmt.Sprintf("<14>1 %s %s %s - - - %s", at.Format("2006-01-02T15:04:05.000000Z"), token(s.Host), token(app), line)
	rec := source.Record{Channel: s.Channel(), RecordID: rid, CreatedAt: at, ReadAt: at, Raw: raw, Source: SourceName}
	if truncated {
		rec.Truncated, rec.OriginalSize = true, size
	}
	return rec
}

// token: pole nagłówka RFC 5424 – bez spacji, „-” gdy puste.
func token(v string) string {
	v = strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return -1
		}
		return r
	}, v)
	if v == "" {
		return "-"
	}
	if len(v) > 48 {
		v = v[:48]
	}
	return v
}
