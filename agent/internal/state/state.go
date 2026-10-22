// SPDX-License-Identifier: AGPL-3.0-or-later

// Package state przechowuje potwierdzone pozycje odczytu (bookmarki) agenta.
//
// Stan jest zapisywany w dwóch miejscach: w pliku state.json (po każdym
// potwierdzeniu) i w kopii zapasowej (rejestr Windows, rzadziej). Kopia pełni
// też rolę znacznika „agent już działał” – dzięki niej utrata pliku stanu nie
// jest mylona z pierwszym uruchomieniem, które zaczyna odczyt „od teraz”
// i zostawiłoby lukę w danych.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
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

func empty() State { return State{Channels: map[string]ChannelState{}} }

// Origin mówi, skąd pochodzi wczytany stan.
type Origin int

const (
	// OriginFresh: pierwsze uruchomienie (brak pliku i brak znacznika).
	OriginFresh Origin = iota
	// OriginFile: stan wczytany z pliku – normalna sytuacja.
	OriginFile
	// OriginBackup: plik stanu zniknął lub jest uszkodzony, stan odtworzono
	// z kopii zapasowej (możliwe duplikaty, brak luk).
	OriginBackup
	// OriginLost: agent już działał, ale nie ma ani pliku, ani pozycji
	// w kopii – odczyt trzeba zacząć od najstarszych zdarzeń.
	OriginLost
)

func (o Origin) String() string {
	return [...]string{"fresh", "file", "backup", "lost"}[o]
}

// Backup to druga kopia stanu i znacznik wcześniejszego działania agenta.
type Backup interface {
	// Load zwraca kopię stanu; exists=false oznacza brak znacznika (agent
	// nigdy wcześniej nie działał z tym katalogiem stanu).
	Load() (st State, exists bool, err error)
	Save(State) error
}

// Store zapisuje stan atomowo do pliku JSON i do kopii zapasowej.
type Store struct {
	dir  string
	path string

	// Backup (opcjonalny) – kopia zapasowa i znacznik.
	Backup Backup
	// BackupEvery ogranicza częstotliwość zapisu kopii. Starsza kopia
	// oznacza po odtworzeniu tylko duplikaty, nigdy luki.
	BackupEvery time.Duration
	// OnRecreate jest wywoływane, gdy katalog stanu zniknął i został
	// utworzony ponownie (np. w celu ustawienia uprawnień i zgłoszenia).
	OnRecreate func(dir string) error

	lastBackup time.Time
	now        func() time.Time
}

// NewStore tworzy magazyn stanu w podanym katalogu.
func NewStore(dir string) *Store {
	return &Store{dir: dir, path: filepath.Join(dir, "state.json"), BackupEvery: 30 * time.Second, now: time.Now}
}

// Load wczytuje stan i określa jego pochodzenie.
func (s *Store) Load() (State, Origin, error) {
	st, fileErr := s.readFile()
	if fileErr == nil {
		if s.Backup != nil {
			if _, exists, err := s.Backup.Load(); err == nil && !exists {
				// Uzupełnij brakujący znacznik (np. po aktualizacji agenta).
				_ = s.Backup.Save(st)
			}
		}
		return st, OriginFile, nil
	}
	if !errors.Is(fileErr, fs.ErrNotExist) && !isCorrupt(fileErr) {
		return empty(), OriginFile, fileErr
	}

	if s.Backup == nil {
		if isCorrupt(fileErr) {
			return empty(), OriginLost, nil
		}
		return empty(), OriginFresh, nil
	}
	b, exists, err := s.Backup.Load()
	switch {
	case err != nil:
		return empty(), OriginFile, fmt.Errorf("kopia stanu: %w", err)
	case !exists && !isCorrupt(fileErr):
		return empty(), OriginFresh, nil
	case len(b.Channels) > 0:
		return b, OriginBackup, nil
	default:
		return empty(), OriginLost, nil
	}
}

type corruptError struct{ err error }

func (c corruptError) Error() string { return c.err.Error() }

func isCorrupt(err error) bool {
	var c corruptError
	return errors.As(err, &c)
}

func (s *Store) readFile() (State, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return empty(), err
	}
	st := empty()
	if err := json.Unmarshal(data, &st); err != nil {
		return empty(), corruptError{fmt.Errorf("uszkodzony plik stanu %s: %w", s.path, err)}
	}
	if st.Channels == nil {
		st.Channels = map[string]ChannelState{}
	}
	return st, nil
}

// Missing zwraca true, gdy plik stanu nie istnieje (np. został usunięty).
func (s *Store) Missing() bool {
	_, err := os.Stat(s.path)
	return errors.Is(err, fs.ErrNotExist)
}

// Save zapisuje stan do pliku (przez plik tymczasowy i podmianę, z fsync)
// oraz – nie częściej niż co BackupEvery – do kopii zapasowej. Jeśli katalog
// stanu zniknął, jest tworzony ponownie.
func (s *Store) Save(st State) error {
	err := s.writeFile(st)
	if errors.Is(err, fs.ErrNotExist) {
		if mkErr := os.MkdirAll(s.dir, 0o700); mkErr != nil {
			return mkErr
		}
		if s.OnRecreate != nil {
			if hookErr := s.OnRecreate(s.dir); hookErr != nil {
				return hookErr
			}
		}
		err = s.writeFile(st)
	}
	if err != nil {
		return err
	}
	if s.Backup != nil && (s.lastBackup.IsZero() || s.now().Sub(s.lastBackup) >= s.BackupEvery) {
		if err := s.Backup.Save(st); err != nil {
			return fmt.Errorf("kopia stanu: %w", err)
		}
		s.lastBackup = s.now()
	}
	return nil
}

func (s *Store) writeFile(st State) error {
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
