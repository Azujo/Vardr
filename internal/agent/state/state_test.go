package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memBackup struct {
	st     State
	exists bool
	saves  int
}

func (m *memBackup) Load() (State, bool, error) { return m.st, m.exists, nil }
func (m *memBackup) Save(st State) error {
	m.st = State{Channels: map[string]ChannelState{}}
	for k, v := range st.Channels {
		m.st.Channels[k] = v
	}
	m.exists = true
	m.saves++
	return nil
}

func sample(rec uint64) State {
	return State{Channels: map[string]ChannelState{"Security": {RecordID: rec, Generation: 1}}}
}

func TestLoadMissingAndRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())

	st, origin, err := s.Load()
	if err != nil || len(st.Channels) != 0 || origin != OriginFresh {
		t.Fatalf("pusty stan: %v, %v, %v", st, origin, err)
	}
	if err := s.Save(sample(42)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(sample(43)); err != nil {
		t.Fatal(err)
	}
	got, origin, err := s.Load()
	if err != nil || origin != OriginFile || got.Channels["Security"].RecordID != 43 {
		t.Fatalf("odczytany stan: %+v %v %v", got, origin, err)
	}
}

func TestDeletedStateFileIsRestoredFromBackup(t *testing.T) {
	dir := t.TempDir()
	b := &memBackup{}
	s := NewStore(dir)
	s.Backup = b

	if _, origin, _ := s.Load(); origin != OriginFresh {
		t.Fatalf("pierwsze uruchomienie: %v", origin)
	}
	if err := s.Save(sample(100)); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "state.json")) // „ktoś usunął plik stanu”

	st, origin, err := s.Load()
	if err != nil || origin != OriginBackup || st.Channels["Security"].RecordID != 100 {
		t.Fatalf("odtworzenie z kopii: %+v %v %v", st, origin, err)
	}
}

func TestBackupMarkerWithoutPositionsMeansLost(t *testing.T) {
	s := NewStore(t.TempDir())
	s.Backup = &memBackup{exists: true, st: State{Channels: map[string]ChannelState{}}}

	if _, origin, err := s.Load(); err != nil || origin != OriginLost {
		t.Fatalf("plik usunięty, znacznik bez pozycji: %v %v", origin, err)
	}
}

func TestCorruptFileFallsBackToBackup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{zepsute"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	s.Backup = &memBackup{exists: true, st: sample(7)}
	if st, origin, err := s.Load(); err != nil || origin != OriginBackup || st.Channels["Security"].RecordID != 7 {
		t.Fatalf("uszkodzony plik: %+v %v %v", st, origin, err)
	}

	s.Backup = nil
	if _, origin, err := s.Load(); err != nil || origin != OriginLost {
		t.Fatalf("uszkodzony plik bez kopii powinien oznaczać utratę stanu: %v %v", origin, err)
	}
}

func TestSaveRecreatesDeletedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := NewStore(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	recreated := 0
	s.OnRecreate = func(string) error { recreated++; return nil }

	if err := os.RemoveAll(dir); err != nil { // „ktoś usunął cały katalog”
		t.Fatal(err)
	}
	if !s.Missing() {
		t.Fatal("Missing powinno wykryć brak pliku stanu")
	}
	if err := s.Save(sample(5)); err != nil {
		t.Fatal(err)
	}
	if recreated != 1 || s.Missing() {
		t.Fatalf("katalog nie został odtworzony (hook=%d)", recreated)
	}
}

func TestBackupWritesAreThrottled(t *testing.T) {
	s := NewStore(t.TempDir())
	b := &memBackup{}
	s.Backup = b
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		if err := s.Save(sample(uint64(i))); err != nil {
			t.Fatal(err)
		}
		now = now.Add(5 * time.Second)
	}
	// 50 s przy limicie 30 s → zapis przy 0 s i 30 s.
	if b.saves != 2 {
		t.Fatalf("zapisów kopii: %d, oczekiwano 2", b.saves)
	}
	if b.st.Channels["Security"].RecordID > 9 {
		t.Fatal("kopia nie może wyprzedzać potwierdzonego stanu")
	}
}
