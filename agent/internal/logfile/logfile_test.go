// SPDX-License-Identifier: AGPL-3.0-or-later

package logfile

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRecord(t *testing.T) {
	s := &Source{Path: "/var/log/nginx/access.log", Host: "web01"}
	at := time.Date(2026, 10, 28, 20, 0, 0, 0, time.UTC)
	r := s.Record(`203.0.113.5 - - "GET / HTTP/1.1" 200`, 3<<offsetBits|120, at)
	if r.Raw != `<14>1 2026-10-28T20:00:00.000000Z web01 access - - - 203.0.113.5 - - "GET / HTTP/1.1" 200` ||
		r.Channel != "file:/var/log/nginx/access.log" || r.Source != SourceName || r.RecordID>>offsetBits != 3 || r.Truncated {
		t.Fatalf("%+v", r)
	}
	s.App = "nginx-dostep"
	long := s.Record(strings.Repeat("x", maxLine+10), 1, at)
	if !strings.Contains(long.Raw, " nginx-dostep - - - ") || !long.Truncated || long.OriginalSize != maxLine+10 {
		t.Fatalf("przycięcie: %v %d", long.Truncated, long.OriginalSize)
	}
}

func TestExpand(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.MkdirAll(filepath.Join(dir, "app"), 0o755)
	os.MkdirAll(state, 0o755)
	for _, f := range []string{"a.log", "b.log", "c.txt", "state/agent.log"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o644)
	}
	got := Expand([]string{filepath.Join(dir, "*.log"), filepath.Join(dir, "a.log"), filepath.Join(dir, "*"),
		filepath.Join(dir, "brak.log"), filepath.Join(state, "*.log")}, state)
	want := []string{"a.log", "b.log", "c.txt", "brak.log"}
	for i := range want {
		want[i] = filepath.Join(dir, want[i])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	if AppName("/var/log/nginx/access.log.1") != "access" || AppName("/var/log/syslog") != "syslog" || AppName("/x/.hidden") != ".hidden" {
		t.Fatal("AppName")
	}
}

func TestWaitNew(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "app-1.log")
	os.WriteFile(a, []byte("x\n"), 0o600)
	pat := []string{filepath.Join(dir, "app-*.log")}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if WaitNew(ctx, pat, "", []string{a}, 10*time.Millisecond, nil) {
		t.Fatal("brak nowego pliku, a WaitNew zwrócił true")
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		os.WriteFile(filepath.Join(dir, "app-2.log"), []byte("y\n"), 0o600)
	}()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if !WaitNew(ctx2, pat, "", []string{a}, 10*time.Millisecond, nil) {
		t.Fatal("nowy plik niewykryty")
	}
}
