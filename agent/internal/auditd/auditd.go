// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auditd czyta dziennik Linux Audit (/var/log/audit/audit.log) na
// agencie Linux. Rekordy jednego zdarzenia (ten sam msg=audit(czas:numer):
// SYSCALL, EXECVE, CWD, PATH, PROCTITLE… aż do EOE) trafiają na serwer razem,
// jako jeden rekord (wiersze oddzielone \n, źródło „file:auditd”) – rozbiera
// go wbudowany dekoder linux-audit (parser audit). Wiersze bez „node=”
// dostają nazwę hosta agenta.
//
// Plik jest śledzony z rotacją auditd (audit.log → audit.log.1 …): po
// zmianie pliku pod ścieżką agent doczytuje stary do końca i przechodzi do
// nowego. Pozycja (numer rekordu kanału) to czas zdarzenia w ms w górnych
// bitach i dolne 20 bitów numeru zdarzenia – po restarcie odczyt wznawia
// się od pliku, w którym zaczynają się późniejsze zdarzenia, z pominięciem
// wysłanych. Identyfikator zdarzenia pochodzi z msg=audit(…), więc ponowny
// odczyt nie tworzy duplikatów.
package auditd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"siem/agent/internal/source"
)

// Channel: nazwa kanału w stanie i statusie agenta.
const Channel = "auditd"

// SourceName: źródło zdarzeń w paczce (dekoder linux-audit).
const SourceName = "file:auditd"

// DefaultPath: dziennik auditd.
const DefaultPath = "/var/log/audit/audit.log"

// DefaultExclude: typy rekordów pomijane domyślnie – powtarzają się przy
// każdym zadaniu cron i sesji (logowania i sudo przychodzą jako USER_LOGIN,
// USER_AUTH, USER_CMD) albo przy każdej zmianie kontenerów.
var DefaultExclude = []string{"CRED_ACQ", "CRED_DISP", "CRED_REFR", "USER_ACCT", "USER_START", "USER_END",
	"LOGIN", "SERVICE_START", "SERVICE_STOP", "BPF", "NETFILTER_CFG"}

const (
	maxLine    = 64 << 10 // dłuższe wiersze są przycinane
	maxPending = 64       // zdarzenia czekające na EOE
	groupIdle  = time.Second
	serialBits = 20
)

var headRe = regexp.MustCompile(`^(?:node=\S+ )?type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):`)

// aux: rekordy pomocnicze zdarzenia wywołania systemowego.
var aux = map[string]bool{"SYSCALL": true, "CWD": true, "PATH": true, "PROCTITLE": true, "EOE": true,
	"SOCKADDR": true, "EXECVE": true, "BPRM_FCAPS": true, "OBJ_PID": true, "MMAP": true, "FD_PAIR": true}

// Source czyta dziennik auditd.
type Source struct {
	Path    string          // domyślnie DefaultPath
	Exclude map[string]bool // pomijane typy rekordów
	Oldest  bool            // start_at: oldest – od najstarszego pliku przy pierwszym uruchomieniu
	Host    string          // node= dla wierszy bez nazwy hosta
	SelfExe string          // program agenta – jego wywołania są pomijane (pętla)
	// SelfUpdate: przedrostek programu nowej wersji agenta w trakcie
	// automatycznej aktualizacji (apply-update) – też pomijany.
	SelfUpdate string
	Poll       time.Duration // domyślnie 500 ms
	Log        *slog.Logger
}

func (s *Source) Channel() string { return Channel }

func (s *Source) path() string {
	if s.Path == "" {
		return DefaultPath
	}
	return s.Path
}

// Files zwraca pliki dziennika od najstarszego (audit.log.N … audit.log.1, audit.log).
func Files(path string) []string {
	matches, _ := filepath.Glob(path + ".*")
	type rot struct {
		n    int
		name string
	}
	var rs []rot
	for _, m := range matches {
		if n, err := strconv.Atoi(strings.TrimPrefix(m, path+".")); err == nil && n > 0 {
			rs = append(rs, rot{n, m})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].n > rs[j].n })
	out := make([]string, 0, len(rs)+1)
	for _, r := range rs {
		out = append(out, r.name)
	}
	if _, err := os.Stat(path); err == nil {
		out = append(out, path)
	}
	return out
}

func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	path := s.path()
	// auditd nie musi być zainstalowany – czekanie bez błędu kanału.
	for waited := false; ; waited = true {
		if _, err := os.Stat(path); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return start, err
		}
		if !waited && s.Log != nil {
			s.Log.Info("auditd: no audit log yet – waiting (install auditd to collect Linux Audit events)", "path", path)
		}
		select {
		case <-ctx.Done():
			return start, ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}

	r := &reader{src: s, out: out, pos: start, index: map[string]*group{}}
	if start.Valid {
		r.skipUntil = start.RecordID
		r.last = start.RecordID
	}
	files := Files(path)
	if len(files) == 0 {
		files = []string{path}
	}
	var from int  // indeks pierwszego czytanego pliku
	var off int64 // przesunięcie w bieżącym pliku (gdy zaczynamy od niego)
	switch {
	case start.Valid:
		from = 0
		ms := int64(start.RecordID >> serialBits)
		for i := len(files) - 1; i >= 0; i-- {
			if first, ok := firstMs(files[i]); ok && first <= ms {
				from = i
				break
			}
		}
	case start.Oldest || s.Oldest:
		from = 0
	default:
		from = len(files) - 1
		if fi, err := os.Stat(path); err == nil {
			off = fi.Size()
		}
	}
	// Pliki po rotacji (kompletne).
	for _, f := range files[from : len(files)-1] {
		if err := r.readRotated(ctx, f); err != nil {
			return r.pos, err
		}
	}
	r.flushAll(ctx)
	if ctx.Err() != nil {
		return r.pos, ctx.Err()
	}
	err := r.follow(ctx, path, off)
	return r.pos, err
}

// firstMs: czas pierwszego zdarzenia pliku (ms).
func firstMs(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for i := 0; sc.Scan() && i < 100; i++ {
		if m := headRe.FindStringSubmatch(sc.Text()); m != nil {
			ms, _ := eventMs(m[2], m[3])
			return ms, true
		}
	}
	return 0, false
}

func eventMs(sec, frac string) (int64, error) {
	s, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return 0, err
	}
	ms, _ := strconv.ParseInt((frac + "000")[:3], 10, 64)
	return s*1000 + ms, nil
}

type group struct {
	id     string
	ms     int64
	serial uint64
	lines  []string
	types  []string
	exe    string
	seen   time.Time
}

type reader struct {
	src       *Source
	out       chan<- source.Record
	pos       source.Position
	skipUntil uint64
	last      uint64
	pending   []*group
	index     map[string]*group
}

func (r *reader) readRotated(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // usunięty w międzyczasie przez rotację
	}
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := readLine(br)
		if line != "" {
			if !r.add(ctx, line) {
				return ctx.Err()
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// follow śledzi bieżący plik od przesunięcia off, z obsługą rotacji
// i obcięcia.
func (r *reader) follow(ctx context.Context, path string, off int64) error {
	poll := r.src.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	var f *os.File
	var fi os.FileInfo
	var partial string
	open := func(at int64) error {
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		st, err := nf.Stat()
		if err != nil {
			nf.Close()
			return err
		}
		if at > st.Size() {
			at = 0
		}
		if _, err := nf.Seek(at, io.SeekStart); err != nil {
			nf.Close()
			return err
		}
		if f != nil {
			f.Close()
		}
		f, fi, off, partial = nf, st, at, ""
		return nil
	}
	if err := open(off); err != nil {
		return err
	}
	defer func() { f.Close() }()
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			off += int64(n)
			partial += string(buf[:n])
			for {
				i := strings.IndexByte(partial, '\n')
				if i < 0 {
					if len(partial) > maxLine {
						partial = partial[:maxLine] // bez końca wiersza – przycięcie
					}
					break
				}
				line := strings.TrimRight(partial[:i], "\r")
				partial = partial[i+1:]
				if len(line) > maxLine {
					line = line[:maxLine]
				}
				if line != "" && !r.add(ctx, line) {
					return ctx.Err()
				}
			}
			continue
		}
		if err != nil && err != io.EOF {
			return err
		}
		// Koniec danych: zdarzenia bez EOE po chwili ciszy, potem rotacja.
		r.flushIdle(ctx, time.Now())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
		st, err := os.Stat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue // rotacja w toku
		case err != nil:
			return err
		case !os.SameFile(st, fi):
			// Nowy plik pod ścieżką: dokończ stary, potem nowy od początku.
			if rest, _ := io.ReadAll(f); len(rest) > 0 {
				partial += string(rest)
			}
			if partial != "" {
				for _, l := range strings.Split(strings.TrimRight(partial, "\n"), "\n") {
					if l != "" && !r.add(ctx, l) {
						return ctx.Err()
					}
				}
			}
			r.flushAll(ctx)
			if err := open(0); err != nil {
				return err
			}
		case st.Size() < off:
			if err := open(0); err != nil { // plik obcięty
				return err
			}
		}
	}
}

// add dołącza wiersz do zdarzenia. false – ctx zakończony.
func (r *reader) add(ctx context.Context, line string) bool {
	m := headRe.FindStringSubmatch(line)
	if m == nil {
		return true
	}
	typ := m[1]
	id := m[2] + "." + m[3] + ":" + m[4]
	g := r.index[id]
	if g == nil {
		ms, err := eventMs(m[2], m[3])
		if err != nil {
			return true
		}
		serial, _ := strconv.ParseUint(m[4], 10, 64)
		g = &group{id: id, ms: ms, serial: serial}
		r.index[id] = g
		r.pending = append(r.pending, g)
	}
	if !strings.HasPrefix(line, "node=") && r.src.Host != "" {
		line = "node=" + r.src.Host + " " + line
	}
	g.lines = append(g.lines, line)
	g.types = append(g.types, typ)
	g.seen = time.Now()
	if typ == "SYSCALL" && g.exe == "" {
		g.exe = exeOf(line)
	}
	// Koniec zdarzenia: EOE; rekordy programów (msg='…') i auditd są pojedyncze.
	if typ == "EOE" || strings.Contains(line, " msg='") || strings.HasPrefix(typ, "DAEMON_") {
		return r.emit(ctx, g)
	}
	for len(r.pending) > maxPending {
		if !r.emit(ctx, r.pending[0]) {
			return false
		}
	}
	return true
}

func exeOf(line string) string {
	i := strings.Index(line, ` exe="`)
	if i < 0 {
		return ""
	}
	rest := line[i+6:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func (r *reader) flushIdle(ctx context.Context, now time.Time) {
	for len(r.pending) > 0 && now.Sub(r.pending[0].seen) >= groupIdle {
		if !r.emit(ctx, r.pending[0]) {
			return
		}
	}
}

func (r *reader) flushAll(ctx context.Context) {
	for len(r.pending) > 0 {
		if !r.emit(ctx, r.pending[0]) {
			return
		}
	}
}

// emit wysyła zdarzenie (o ile nie jest pominięte) i usuwa je z oczekujących.
func (r *reader) emit(ctx context.Context, g *group) bool {
	for i, p := range r.pending {
		if p == g {
			r.pending = append(r.pending[:i], r.pending[i+1:]...)
			break
		}
	}
	delete(r.index, g.id)
	if !r.wanted(g) {
		return true
	}
	rid := uint64(g.ms)<<serialBits | g.serial&(1<<serialBits-1)
	if rid <= r.skipUntil {
		return true // wysłane przed restartem
	}
	if rid <= r.last {
		rid = r.last + 1
	}
	h := sha256.Sum256([]byte(g.id))
	rec := source.Record{Channel: Channel, RecordID: rid, CreatedAt: time.UnixMilli(g.ms).UTC(), ReadAt: time.Now().UTC(),
		Raw: strings.Join(g.lines, "\n"), Source: SourceName, Key: hex.EncodeToString(h[:12])}
	select {
	case r.out <- rec:
	case <-ctx.Done():
		return false
	}
	r.last = rid
	r.pos = source.Position{RecordID: rid, Valid: true}
	return true
}

// wanted: zdarzenie nie jest wyłączone (typ) ani wywołaniem samego agenta.
func (r *reader) wanted(g *group) bool {
	if r.src.SelfExe != "" && g.exe == r.src.SelfExe ||
		r.src.SelfUpdate != "" && strings.HasPrefix(g.exe, r.src.SelfUpdate) {
		return false
	}
	main := false
	for _, t := range g.types {
		if !aux[t] {
			main = true
			if !r.src.Exclude[t] {
				return true
			}
		}
	}
	if main {
		return false
	}
	return !r.src.Exclude["SYSCALL"]
}

// readLine czyta wiersz do maxLine bajtów (resztę dłuższego pomija).
func readLine(br *bufio.Reader) (string, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) <= maxLine {
			buf = append(buf, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return strings.TrimRight(string(buf), "\r\n"), err
	}
}
