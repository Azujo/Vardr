// SPDX-License-Identifier: AGPL-3.0-or-later

package logfile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
)

// collect zbiera n rekordów (albo kończy test po czasie).
func collect(t *testing.T, ch <-chan source.Record, n int) []source.Record {
	t.Helper()
	var out []source.Record
	for len(out) < n {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-time.After(5 * time.Second):
			t.Fatalf("po %d rekordach brak kolejnych", len(out))
		}
	}
	return out
}

func msg(r source.Record) string { return r.Raw[strings.Index(r.Raw, " - - - ")+7:] }

func TestFollowRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	os.WriteFile(path, []byte("stary\n"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position, 1)
	s := &Source{Path: path, Host: "h", Poll: 20 * time.Millisecond}
	go func() { p, _ := s.Run(ctx, source.Position{}, out); done <- p }()
	time.Sleep(100 * time.Millisecond) // start od końca pliku

	appendTo := func(text string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(text)
		f.Close()
	}
	appendTo("jeden\ndwa\r\n\nczę")
	time.Sleep(60 * time.Millisecond)
	appendTo("ść\n")
	r := collect(t, out, 3)
	if msg(r[0]) != "jeden" || msg(r[1]) != "dwa" || msg(r[2]) != "część" || r[0].RecordID != 6+6 || r[2].RecordID>>offsetBits != 0 {
		t.Fatalf("%q %q %q %d", msg(r[0]), msg(r[1]), msg(r[2]), r[0].RecordID)
	}
	// logrotate: zmiana nazwy, dopisanie do starego, nowy plik.
	os.Rename(path, path+".1")
	f, _ := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("ostatni w starym")
	f.Close()
	appendTo("nowy\n")
	r = collect(t, out, 2)
	if msg(r[0]) != "ostatni w starym" || msg(r[1]) != "nowy" || r[1].RecordID != 1<<offsetBits|5 {
		t.Fatalf("rotacja: %q %q %x", msg(r[0]), msg(r[1]), r[1].RecordID)
	}
	// copytruncate: obcięcie i nowe wiersze.
	time.Sleep(60 * time.Millisecond)
	os.Truncate(path, 0)
	time.Sleep(60 * time.Millisecond)
	appendTo("po obcięciu\n")
	r = collect(t, out, 1)
	if msg(r[0]) != "po obcięciu" || r[0].RecordID>>offsetBits != 2 {
		t.Fatalf("obcięcie: %q %x", msg(r[0]), r[0].RecordID)
	}
	cancel()
	pos := <-done
	if !pos.Valid || pos.RecordID != r[0].RecordID {
		t.Fatalf("pozycja: %+v", pos)
	}

	// Wznowienie: bez powtórzeń; plik krótszy niż pozycja – od początku, nowa generacja.
	run := func(p source.Position) func() {
		ctx, cancel := context.WithCancel(context.Background())
		end := make(chan struct{})
		go func() { _, _ = s.Run(ctx, p, out); close(end) }()
		return func() { cancel(); <-end }
	}
	appendTo("po restarcie\n")
	stop := run(pos)
	r = collect(t, out, 1)
	stop()
	if msg(r[0]) != "po restarcie" || r[0].RecordID>>offsetBits != 2 {
		t.Fatalf("wznowienie: %q %x", msg(r[0]), r[0].RecordID)
	}
	os.WriteFile(path, []byte("x\n"), 0o644)
	stop = run(source.Position{RecordID: r[0].RecordID, Valid: true})
	defer stop()
	r = collect(t, out, 1)
	if msg(r[0]) != "x" || r[0].RecordID != 3<<offsetBits|2 {
		t.Fatalf("po rotacji w czasie przerwy: %q %x", msg(r[0]), r[0].RecordID)
	}
}
