// SPDX-License-Identifier: AGPL-3.0-or-later

// Package langdb to język systemu dla usług serwera – odczyt z Sagi
// (widok public.system_language, ustawienie administratora w panelu).
package langdb

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"siem/internal/lang"
)

// Querier: połączenie z Sagą (pgxpool.Pool, pgx.Conn).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// System to język systemu odczytywany z Sagi najwyżej co 30 s. Brak
// widoku albo uprawnień (starszy panel) – lang.Default.
type System struct {
	DB Querier

	mu sync.Mutex
	v  string
	at time.Time
}

// Get zwraca język systemu.
func (s *System) Get(ctx context.Context) string {
	if s == nil || s.DB == nil {
		return lang.Default
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v != "" && time.Since(s.at) < 30*time.Second {
		return s.v
	}
	var v string
	err := s.DB.QueryRow(ctx, `SELECT language FROM public.system_language`).Scan(&v)
	switch {
	case err == nil && (v == "pl" || v == "en"):
	case err != nil && !errors.Is(err, pgx.ErrNoRows) && s.v != "":
		return s.v // chwilowy błąd – poprzedni odczyt
	default:
		v = lang.Default
	}
	s.v, s.at = v, time.Now()
	return v
}
