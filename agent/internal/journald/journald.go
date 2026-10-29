// SPDX-License-Identifier: AGPL-3.0-or-later

// Package journald czyta dziennik systemd (agent Linux) przez
// „journalctl -o json --follow” – bez cgo i biblioteki libsystemd. Każdy wpis
// trafia na serwer jako linia syslog RFC 5424 (źródło „syslog:journald”), więc
// działają te same dekodery i reguły co dla Linuksa przez rsyslog (sshd, sudo,
// su, PAM, zmiany kont).
//
// Pozycja odczytu: czas wpisu (__REALTIME_TIMESTAMP, µs od 1970) – numer
// rekordu kanału. Po restarcie odczyt wznawia się od tej chwili
// (journalctl --since), z pominięciem wpisów już wysłanych. Numer jest
// niemalejący (cofnięcie zegara podbija go o 1), a identyfikator zdarzenia
// pochodzi z kursora wpisu – ponowny odczyt nie tworzy duplikatów.
package journald

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"siem/agent/internal/source"
	"siem/internal/lang"
)

// Channel: nazwa kanału w stanie i statusie agenta.
const Channel = "journald"

// SourceName: źródło zdarzeń w paczce (ścieżka syslog na serwerze).
const SourceName = "syslog:journald"

// OwnUnit: jednostka agenta – jego własne wpisy są pomijane (pętla).
const OwnUnit = "vardr-agent.service"

// maxLine: najdłuższa linia JSON z journalctl (dłuższe wpisy są przycinane).
const maxLine = 1 << 20

// ErrNotFound: brak programu journalctl (system bez systemd).
var ErrNotFound = errors.New("journalctl not found")

// Filter wybiera wpisy dziennika.
type Filter struct {
	All         bool     // wszystkie wpisy
	Units       []string // jednostki systemd w całości
	Identifiers []string // programy (SYSLOG_IDENTIFIER) w całości
}

// Matches: argumenty dopasowań journalctl. Grupy rozdziela „+” (lub);
// powtórzone pole w grupie to też „lub”. Domyślnie: auth (4) i authpriv (10)
// oraz priorytety 0–4 (emerg … warning).
func (f Filter) Matches() []string {
	if f.All {
		return nil
	}
	m := []string{"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+",
		"PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3", "PRIORITY=4"}
	for _, u := range f.Units {
		m = append(m, "+", "_SYSTEMD_UNIT="+u)
	}
	for _, id := range f.Identifiers {
		m = append(m, "+", "SYSLOG_IDENTIFIER="+id)
	}
	return m
}

// Source czyta dziennik systemd.
type Source struct {
	Journalctl string // domyślnie journalctl z PATH
	Filter     Filter
	Oldest     bool // start_at: oldest – cały dziennik przy pierwszym uruchomieniu
	Host       string
	Log        *slog.Logger
}

func (s *Source) Channel() string { return Channel }

// Args: argumenty journalctl dla pozycji startowej.
func (s *Source) Args(start source.Position) []string {
	args := []string{"--output=json", "--follow", "--no-pager", "--quiet", "--all"}
	switch {
	case start.Valid:
		us := int64(start.RecordID)
		args = append(args, fmt.Sprintf("--since=@%d.%06d", us/1e6, us%1e6))
	case start.Oldest || s.Oldest:
		// od najstarszego wpisu
	default:
		args = append(args, "--lines=0") // tylko nowe wpisy
	}
	return append(args, s.Filter.Matches()...)
}

func (s *Source) Run(ctx context.Context, start source.Position, out chan<- source.Record) (source.Position, error) {
	bin := s.Journalctl
	if bin == "" {
		bin = "journalctl"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return start, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	cmd := exec.CommandContext(ctx, path, s.Args(start)...)
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return start, err
	}
	var stderr tail
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return start, err
	}
	pos := start
	rerr := s.read(ctx, stdout, &pos, out)
	if rerr != nil {
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return pos, ctx.Err()
	}
	if rerr != nil {
		return pos, rerr
	}
	msg := strings.TrimSpace(stderr.String())
	if werr != nil {
		if msg != "" {
			return pos, lang.Errorf("journalctl: %v: %s", "journalctl: %v: %s", werr, msg)
		}
		return pos, lang.Errorf("journalctl: %w", "journalctl: %w", werr)
	}
	return pos, lang.Errorf("journalctl zakończył się nieoczekiwanie %s", "journalctl ended unexpectedly %s", msg)
}

// read przekazuje wpisy z wyjścia journalctl, aż do jego końca albo ctx.
func (s *Source) read(ctx context.Context, r io.Reader, pos *source.Position, out chan<- source.Record) error {
	br := bufio.NewReaderSize(r, 64<<10)
	skipUntil := uint64(0)
	if pos.Valid {
		skipUntil = pos.RecordID // wpisy do tej chwili włącznie już wysłano
	}
	last := pos.RecordID
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			rec, ok := s.Record(line, last)
			if ok {
				if uint64(rec.CreatedAt.UnixMicro()) <= skipUntil {
					continue
				}
				select {
				case out <- rec:
				case <-ctx.Done():
					return nil
				}
				last = rec.RecordID
				*pos = source.Position{RecordID: last, Valid: true}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readLine czyta linię do maxLine bajtów (resztę dłuższej pomija).
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) <= maxLine {
			buf = append(buf, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}

// Record zamienia wpis JSON journalctl na rekord źródła. last – numer
// poprzedniego rekordu (numer jest niemalejący).
func (s *Source) Record(line []byte, last uint64) (source.Record, bool) {
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		if s.Log != nil {
			s.Log.Warn("journald: unreadable entry", "err", err)
		}
		return source.Record{}, false
	}
	if field(e, "_SYSTEMD_UNIT") == OwnUnit {
		return source.Record{}, false
	}
	us, err := strconv.ParseUint(field(e, "__REALTIME_TIMESTAMP"), 10, 64)
	if err != nil || us == 0 {
		return source.Record{}, false
	}
	at := time.UnixMicro(int64(us)).UTC()
	rid := us
	if rid <= last {
		rid = last + 1
	}
	fac, sev := number(e, "SYSLOG_FACILITY", 3), number(e, "PRIORITY", 6)
	if field(e, "_TRANSPORT") == "kernel" {
		fac = 0
	}
	if fac < 0 || fac > 23 {
		fac = 3
	}
	if sev < 0 || sev > 7 {
		sev = 6
	}
	host := token(field(e, "_HOSTNAME"))
	if host == "-" {
		host = token(s.Host)
	}
	app := field(e, "SYSLOG_IDENTIFIER")
	if app == "" {
		app = field(e, "_COMM")
	}
	pid := field(e, "SYSLOG_PID")
	if pid == "" {
		pid = field(e, "_PID")
	}
	msg := field(e, "MESSAGE")
	raw := fmt.Sprintf("<%d>1 %s %s %s %s - - %s", fac*8+sev, at.Format("2006-01-02T15:04:05.000000Z"),
		host, token(app), token(pid), msg)
	rec := source.Record{Channel: Channel, RecordID: rid, CreatedAt: at, ReadAt: time.Now().UTC(), Raw: raw, Source: SourceName}
	if c := field(e, "__CURSOR"); c != "" {
		h := sha256.Sum256([]byte(c))
		rec.Key = hex.EncodeToString(h[:12])
	}
	return rec, true
}

// field: wartość pola wpisu. journalctl zapisuje wartości niebędące
// poprawnym UTF-8 jako tablicę bajtów, a pole powtórzone – jako tablicę wartości.
func field(e map[string]any, k string) string {
	switch v := e[k].(type) {
	case string:
		return v
	case []any:
		if len(v) == 0 {
			return ""
		}
		if _, ok := v[0].(float64); ok {
			b := make([]byte, 0, len(v))
			for _, x := range v {
				if f, ok := x.(float64); ok {
					b = append(b, byte(f))
				}
			}
			return strings.ToValidUTF8(string(b), "�")
		}
		if s, ok := v[0].(string); ok {
			return s
		}
	}
	return ""
}

func number(e map[string]any, k string, def int) int {
	n, err := strconv.Atoi(field(e, k))
	if err != nil {
		return def
	}
	return n
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

// tail: ostatnie bajty stderr journalctl (opis błędu).
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2048 {
		t.b = t.b[len(t.b)-2048:]
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.b) }
