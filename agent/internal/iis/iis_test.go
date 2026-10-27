// SPDX-License-Identifier: AGPL-3.0-or-later

package iis

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"siem/agent/internal/source"
)

const header = "#Software: Microsoft Internet Information Services 10.0\r\n#Version: 1.0\r\n#Date: 2026-10-27 00:00:00\r\n" +
	"#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status time-taken\r\n"

func line(t, user, status string) string {
	return "2026-10-27 " + t + " 10.0.0.5 POST /owa/auth.owa - 443 " + user + " 203.0.113.7 Mozilla/5.0+(Windows) " + status + " 15\r\n"
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// run uruchamia źródło i zbiera want rekordów (albo kończy po czasie).
func run(t *testing.T, s *Source, start source.Position, want int) ([]source.Record, source.Position) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position, 1)
	go func() { p, _ := s.Run(ctx, start, out); done <- p }()
	var got []source.Record
	deadline := time.After(3 * time.Second)
	for len(got) < want {
		select {
		case r := <-out:
			got = append(got, r)
		case <-deadline:
			t.Fatalf("odebrano %d z %d rekordów", len(got), want)
		}
	}
	select {
	case r := <-out:
		t.Fatalf("nadmiarowy rekord %s", r.Raw)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	return got, <-done
}

func TestIISTail(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "W3SVC1")
	os.MkdirAll(dir, 0o755)
	os.MkdirAll(filepath.Join(root, "pusty"), 0o755)
	f1 := filepath.Join(dir, "u_ex261027.log")
	appendTo(t, f1, header+line("10:00:01", "jkowalski", "200")+line("10:00:02", "-", "401"))

	sites, err := Sites(root)
	if err != nil || len(sites) != 1 || sites[0] != dir {
		t.Fatalf("witryny %v %v", sites, err)
	}
	s := &Source{Dir: dir, Host: "srv-www", Log: slog.New(slog.DiscardHandler), Poll: 10 * time.Millisecond, Settle: 50 * time.Millisecond}
	if s.Channel() != "iis:W3SVC1" {
		t.Fatal(s.Channel())
	}
	got, pos := run(t, s, source.Position{}, 2)
	var m map[string]string
	if err := json.Unmarshal([]byte(got[0].Raw), &m); err != nil {
		t.Fatal(err)
	}
	if m["cs-username"] != "jkowalski" || m["c-ip"] != "203.0.113.7" || m["cs(User-Agent)"] != "Mozilla/5.0+(Windows)" ||
		m["site"] != "W3SVC1" || m["host"] != "srv-www" || m["cs-uri-query"] != "" || got[0].Source != SourceName {
		t.Fatalf("rekord %v", m)
	}
	if !got[0].CreatedAt.Equal(time.Date(2026, 10, 27, 10, 0, 1, 0, time.UTC)) {
		t.Fatal(got[0].CreatedAt)
	}
	m = nil
	json.Unmarshal([]byte(got[1].Raw), &m)
	if _, ok := m["cs-username"]; ok || got[1].RecordID <= got[0].RecordID || pos.RecordID != got[1].RecordID {
		t.Fatalf("drugi rekord %v, pozycje %d %d %d", m, got[0].RecordID, got[1].RecordID, pos.RecordID)
	}

	// Wznowienie: niepełny wiersz czeka, nowy plik z innym #Fields.
	appendTo(t, f1, line("10:00:03", "anowak", "200")+"2026-10-27 10:00:04 10.0.0.5 GET")
	f2 := filepath.Join(dir, "u_ex261028.log")
	appendTo(t, f2, "#Fields: date time c-ip sc-status\r\n2026-10-28 00:00:01 198.51.100.1 404\r\n")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(f1, old, old)
	got, pos = run(t, s, pos, 2)
	m = nil
	json.Unmarshal([]byte(got[0].Raw), &m)
	if m["cs-username"] != "anowak" {
		t.Fatalf("po wznowieniu %v", m)
	}
	m = nil
	json.Unmarshal([]byte(got[1].Raw), &m)
	if m["c-ip"] != "198.51.100.1" || m["sc-status"] != "404" || len(m) != 6 || got[1].RecordID <= got[0].RecordID {
		t.Fatalf("nowy plik %v", m)
	}

	// Bez pozycji: tylko najnowszy plik; Oldest – od najstarszego.
	if got, _ := run(t, s, source.Position{}, 1); got[0].RecordID>>offsetBits != pos.RecordID>>offsetBits {
		t.Fatal("start nie od najnowszego pliku")
	}
	run(t, s, source.Position{Oldest: true}, 4)
}

func TestIISHourlyNames(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"u_ex2610271.log", "u_ex26102713.log", "u_ex26102709_x.log", "u_ex261027.log", "inny.log"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o644)
	}
	files, _ := logFiles(dir)
	if len(files) != 3 || filepath.Base(files[0].path) != "u_ex261027.log" || filepath.Base(files[2].path) != "u_ex26102713.log" {
		t.Fatalf("%v", files)
	}
}
