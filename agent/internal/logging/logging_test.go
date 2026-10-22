// SPDX-License-Identifier: AGPL-3.0-or-later

package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingFileKeepsLimitedHistory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.log")
	r, err := OpenRotating(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 39) + "\n") // 40 B
	for i := 0; i < 20; i++ {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()

	for _, name := range []string{"agent.log", "agent.log.1", "agent.log.2"} {
		fi, err := os.Stat(filepath.Join(filepath.Dir(p), name))
		if err != nil {
			t.Fatalf("brak %s: %v", name, err)
		}
		if fi.Size() > 100 {
			t.Errorf("%s ma %d B, limit 100", name, fi.Size())
		}
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Error("zachowano więcej plików niż keep=2")
	}
}

type fakeSink struct{ entries []string }

func (f *fakeSink) Info(_ uint32, m string) error { f.entries = append(f.entries, "I:"+m); return nil }
func (f *fakeSink) Warning(_ uint32, m string) error {
	f.entries = append(f.entries, "W:"+m)
	return nil
}
func (f *fakeSink) Error(_ uint32, m string) error { f.entries = append(f.entries, "E:"+m); return nil }

func TestSinkHandlerFiltersAndDeduplicates(t *testing.T) {
	sink := &fakeSink{}
	h := NewSinkHandler(sink, 10*time.Minute)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h.state.now = func() time.Time { return now }
	log := slog.New(h).With("agent_id", "agt-1")

	log.Info("zwykła informacja")                        // pomijana
	log.Info("agent uruchomiony", "eventlog", true)      // wymuszona
	log.Warn("wysyłka nieudana", "attempt", 1)           // trafia
	log.Warn("wysyłka nieudana", "attempt", 2)           // tłumiona (ten sam komunikat)
	log.Error("paczka w kwarantannie", "batch_id", "b1") // trafia
	now = now.Add(11 * time.Minute)
	log.Warn("wysyłka nieudana", "attempt", 9) // okno minęło – trafia

	if len(sink.entries) != 4 {
		t.Fatalf("wpisy w dzienniku: %q", sink.entries)
	}
	if !strings.HasPrefix(sink.entries[0], "I:agent uruchomiony") || strings.Contains(sink.entries[0], "eventlog") {
		t.Errorf("wpis startowy: %q", sink.entries[0])
	}
	if !strings.Contains(sink.entries[1], "agent_id: agt-1") || !strings.Contains(sink.entries[1], "attempt: 1") {
		t.Errorf("brak atrybutów w ostrzeżeniu: %q", sink.entries[1])
	}
	if !strings.HasPrefix(sink.entries[3], "W:") || !strings.Contains(sink.entries[3], "attempt: 9") {
		t.Errorf("po oknie tłumienia: %q", sink.entries[3])
	}
}

func TestLevel(t *testing.T) {
	if l, err := Level("warn"); err != nil || l != slog.LevelWarn {
		t.Fatal(l, err)
	}
	if _, err := Level("gadatliwy"); err == nil {
		t.Fatal("oczekiwano błędu")
	}
}
