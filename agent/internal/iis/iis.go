// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iis to źródło logów agenta: pliki IIS w formacie W3C
// (C:\inetpub\logs\LogFiles\W3SVC<n>\u_exRRMMDD.log). Każdy katalog witryny
// to osobny kanał („iis:W3SVC1”); wiersz pliku trafia na serwer jako rekord
// JSON (nazwy pól z dyrektywy #Fields), źródło „file:iis” – rozbiera go
// dekoder wbudowany „iis”.
//
// Pozycja w kanale (RecordID) to godzina pliku z nazwy (od 2000 r.) w górnych
// bitach i przesunięcie za ostatnim wysłanym wierszem w dolnych 40 bitach –
// rośnie razem z plikami, więc wznowienie po restarcie nie gubi ani nie
// powtarza wierszy.
package iis

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"siem/agent/internal/source"
)

// SourceName: źródło zdarzeń w paczce.
const SourceName = "file:iis"

// DefaultDir: domyślny katalog logów IIS.
const DefaultDir = `C:\inetpub\logs\LogFiles`

const (
	offsetBits = 40
	offsetMask = 1<<offsetBits - 1
	// maxLine: dłuższy wiersz jest przycinany (IIS ma limit ok. 4 KB na pole).
	maxLine = 64 << 10
)

var (
	epoch    = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	logName  = regexp.MustCompile(`(?i)^u_ex(\d{6})(\d{2})?(?:_x)?\.log$`)
	errNoDir = errors.New("IIS log directory not found")
)

// Sites zwraca katalogi witryn z logami W3C w dir (podkatalogi z plikami
// u_ex*.log; także sam dir, gdy ma takie pliki).
func Sites(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", errNoDir, dir)
		}
		return nil, err
	}
	var out []string
	if hasLogs(dir) {
		out = append(out, dir)
	}
	for _, e := range ents {
		if e.IsDir() && hasLogs(filepath.Join(dir, e.Name())) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

func hasLogs(dir string) bool {
	files, _ := logFiles(dir)
	return len(files) > 0
}

type logFile struct {
	path string
	key  uint64 // godziny od 2000-01-01 wg nazwy pliku
}

// logFiles: pliki W3C katalogu od najstarszego.
func logFiles(dir string) ([]logFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []logFile
	for _, e := range ents {
		m := logName.FindStringSubmatch(e.Name())
		if m == nil || e.IsDir() {
			continue
		}
		hour := "00"
		if m[2] != "" {
			hour = m[2]
		}
		t, err := time.Parse("060102 15", m[1]+" "+hour)
		if err != nil || t.Before(epoch) {
			continue
		}
		out = append(out, logFile{path: filepath.Join(dir, e.Name()), key: uint64(t.Sub(epoch) / time.Hour)})
	}
	slices.SortFunc(out, func(a, b logFile) int { return int(a.key) - int(b.key) })
	return out, nil
}

// Source czyta pliki jednej witryny.
type Source struct {
	Dir  string // katalog witryny, np. …\LogFiles\W3SVC1
	Host string // nazwa komputera (pole „host” rekordu)
	Log  *slog.Logger
	// Poll: odstęp sprawdzania nowych wierszy (domyślnie 2 s); Settle: jak
	// długo plik musi być niezmieniony, zanim agent przejdzie do nowszego
	// (IIS dopisuje bufor do starego pliku jeszcze chwilę po zmianie dnia).
	Poll, Settle time.Duration
}

// Channel: „iis:<katalog witryny>”.
func (s *Source) Channel() string { return "iis:" + filepath.Base(s.Dir) }

// Run czyta wiersze od pozycji start. Bez pozycji – od początku najnowszego
// pliku (start.Oldest: od najstarszego), żeby nowe źródło nie wysyłało
// całej historii logów.
func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	if s.Poll == 0 {
		s.Poll = 2 * time.Second
	}
	if s.Settle == 0 {
		s.Settle = 2 * time.Minute
	}
	last := start
	var cur logFile
	var off int64
	files, err := logFiles(s.Dir)
	if err != nil {
		return last, err
	}
	switch {
	case start.Valid:
		cur, off = logFile{key: start.RecordID >> offsetBits}, int64(start.RecordID&offsetMask)
		if i := slices.IndexFunc(files, func(f logFile) bool { return f.key >= cur.key }); i >= 0 {
			if files[i].key != cur.key {
				off = 0 // plik pozycji usunięty – następny od początku
			}
			cur = files[i]
		} else {
			cur = logFile{}
		}
	case len(files) == 0:
	case start.Oldest:
		cur = files[0]
	default:
		cur = files[len(files)-1]
	}

	for {
		if cur.path != "" {
			n, pos, end, err := s.readFile(ctx, cur, off, out)
			if n > 0 {
				last = pos
			}
			if err != nil {
				return last, err
			}
			off = end
		}
		// Nowszy plik: przejście, gdy bieżący się nie zmienia (dopisany do końca).
		files, err := logFiles(s.Dir)
		if err != nil {
			return last, err
		}
		if i := slices.IndexFunc(files, func(f logFile) bool { return f.key > cur.key }); i >= 0 {
			if cur.path == "" || s.settled(cur.path, off) {
				cur, off = files[i], 0
				continue
			}
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(s.Poll):
		}
	}
}

// settled: plik niezmieniany od Settle (albo usunięty) – pełne wiersze są
// już przeczytane, a niepełny na końcu (przerwany zapis) nie zostanie
// dokończony.
func (s *Source) settled(path string, off int64) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	if time.Since(fi.ModTime()) < s.Settle {
		return false
	}
	if fi.Size() > off {
		s.Log.Warn("IIS log file ends with an incomplete line – skipped", "file", path, "bytes", fi.Size()-off)
	}
	return true
}

// readFile wysyła pełne wiersze pliku od przesunięcia off (do końca pliku).
// Zwraca liczbę wysłanych rekordów, pozycję ostatniego i przesunięcie za
// ostatnim przeczytanym pełnym wierszem (także komentarzem).
func (s *Source) readFile(ctx context.Context, f logFile, off int64, out chan<- source.Record) (n int, pos source.Position, end int64, err error) {
	end = off
	fh, err := os.Open(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, pos, end, nil
		}
		return 0, pos, end, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return 0, pos, end, err
	}
	if fi.Size() < off {
		s.Log.Warn("IIS log file shrank – reading it again from the start", "file", f.path)
		off, end = 0, 0
	}
	if fi.Size() == off {
		return 0, pos, end, nil
	}
	// Dyrektywa #Fields obowiązująca w miejscu wznowienia.
	fields, err := fieldsBefore(fh, off)
	if err != nil {
		return 0, pos, end, err
	}
	if _, err := fh.Seek(off, io.SeekStart); err != nil {
		return 0, pos, end, err
	}
	r := bufio.NewReaderSize(fh, 64<<10)
	site := filepath.Base(s.Dir)
	for {
		line, size, err := readLine(r)
		if err != nil {
			return n, pos, end, nil // EOF albo niepełny wiersz – dokończymy później
		}
		off += int64(size)
		if off > offsetMask {
			return n, pos, end, fmt.Errorf("IIS log file %s is larger than 1 TB", f.path)
		}
		end = off
		text := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(text, "#") {
			if v, ok := strings.CutPrefix(text, "#Fields:"); ok {
				fields = strings.Fields(v)
			}
			continue
		}
		if strings.TrimSpace(text) == "" || len(fields) == 0 {
			continue
		}
		raw, at := record(fields, text, site, s.Host)
		rec := source.Record{Channel: s.Channel(), RecordID: f.key<<offsetBits | uint64(off), Raw: raw,
			Source: SourceName, ReadAt: time.Now().UTC(), CreatedAt: at,
			Truncated: size > maxLine, OriginalSize: size}
		select {
		case out <- rec:
		case <-ctx.Done():
			return n, pos, end, ctx.Err()
		}
		n++
		pos = source.Position{RecordID: rec.RecordID, Valid: true}
	}
}

// readLine czyta jeden pełny wiersz (z „\n”), przycinając treść do maxLine.
// size: rozmiar wiersza w pliku. Błąd przy końcu pliku bez „\n”.
func readLine(r *bufio.Reader) (line string, size int, err error) {
	var b strings.Builder
	for {
		chunk, err := r.ReadSlice('\n')
		size += len(chunk)
		if b.Len() < maxLine {
			b.Write(chunk[:min(len(chunk), maxLine-b.Len())])
		}
		switch {
		case err == nil:
			return b.String(), size, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", size, err
		}
	}
}

// fieldsBefore: ostatnia dyrektywa #Fields przed przesunięciem off.
func fieldsBefore(fh *os.File, off int64) ([]string, error) {
	if off == 0 {
		return nil, nil
	}
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var fields []string
	r := bufio.NewReaderSize(io.LimitReader(fh, off), 64<<10)
	for {
		line, _, err := readLine(r)
		if err != nil {
			return fields, nil
		}
		if v, ok := strings.CutPrefix(line, "#Fields:"); ok {
			fields = strings.Fields(v)
		}
	}
}

// record zamienia wiersz W3C na JSON: pole → wartość („-” = brak), plus
// site i host. at: czas z pól date i time (W3C – zawsze UTC).
func record(fields []string, line, site, host string) (string, time.Time) {
	vals := strings.Split(line, " ")
	m := make(map[string]string, len(fields)+2)
	for i, f := range fields {
		if i < len(vals) && vals[i] != "-" && vals[i] != "" {
			m[f] = vals[i]
		}
	}
	m["site"] = site
	if host != "" {
		m["host"] = host
	}
	var at time.Time
	if d, t := m["date"], m["time"]; d != "" && t != "" {
		at, _ = time.Parse("2006-01-02 15:04:05", d+" "+t)
	}
	raw, _ := json.Marshal(m)
	return string(raw), at
}
