// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logging zawiera rotowany plik logu oraz przekazywanie ostrzeżeń
// i błędów agenta do Windows Event Log.
package logging

import (
	"fmt"
	"os"
	"sync"
)

// RotatingFile to plik logu z rotacją według rozmiaru w trakcie pracy:
// agent.log → agent.log.1 → … → agent.log.N (najstarszy jest usuwany).
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// OpenRotating otwiera (lub tworzy) plik logu.
func OpenRotating(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if keep < 1 {
		keep = 1
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

// Write zapisuje wpis, rotując plik przed przekroczeniem limitu.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			// Rotacja nieudana (np. plik zablokowany) – piszemy dalej do
			// bieżącego pliku zamiast gubić wpisy.
			fmt.Fprintln(os.Stderr, "log rotation failed:", err)
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	renameErr := os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		return err
	}
	return renameErr
}

// Close zamyka plik.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
