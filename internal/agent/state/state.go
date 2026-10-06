// Package state przechowuje potwierdzone pozycje odczytu (bookmarki) agenta.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ChannelState to ostatni rekord kanału potwierdzony przez serwer.
type ChannelState struct {
	RecordID   uint64 `json:"record_id"`
	Generation uint32 `json:"generation"`
}

// State to pełny stan agenta zapisywany na dysku.
type State struct {
	Channels map[string]ChannelState `json:"channels"`
}

// Store zapisuje stan atomowo do pliku JSON.
type Store struct {
	path string
}

// NewStore tworzy magazyn stanu w podanym katalogu.
func NewStore(dir string) *Store {
	return &Store{path: filepath.Join(dir, "state.json")}
}

// Load wczytuje stan. Brak pliku oznacza pusty stan (pierwsze uruchomienie).
func (s *Store) Load() (State, error) {
	st := State{Channels: map[string]ChannelState{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("uszkodzony plik stanu %s: %w", s.path, err)
	}
	if st.Channels == nil {
		st.Channels = map[string]ChannelState{}
	}
	return st, nil
}

// Save zapisuje stan przez plik tymczasowy i podmianę, z fsync, żeby awaria
// zasilania w trakcie zapisu nie zostawiła połowicznego pliku.
func (s *Store) Save(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
