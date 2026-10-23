// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syslang to język systemu – ustawienie administratora panelu
// (panel_settings), w którym powstają treści wychodzące poza panel:
// powiadomienia na kanałach i szkice zgłoszeń NIS2. Język interfejsu
// wybiera każdy użytkownik osobno (konto).
package syslang

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"siem/panel/internal/api/store"
)

// Key: klucz ustawienia w panel_settings.
const Key = "system_language"

// Default: język systemu bez ustawienia (dotychczasowe instalacje).
const Default = "pl"

// Supported: języki treści tworzonych przez serwer.
var Supported = []string{"pl", "en"}

// Store czyta ustawienie (store.PG).
type Store interface {
	Setting(ctx context.Context, key string) (string, error)
}

// Cache to język systemu odczytywany najwyżej co 30 s.
type Cache struct {
	Store Store
	Log   *slog.Logger

	mu sync.Mutex
	v  string
	at time.Time
}

// Get zwraca język systemu (Default, gdy brak ustawienia albo błąd odczytu).
func (c *Cache) Get(ctx context.Context) string {
	if c == nil || c.Store == nil {
		return Default
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v != "" && time.Since(c.at) < 30*time.Second {
		return c.v
	}
	v, err := c.Store.Setting(ctx, Key)
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && !slices.Contains(Supported, v)):
		v = Default
	case err != nil:
		if c.Log != nil {
			c.Log.Warn("reading the system language failed", "err", err)
		}
		if c.v != "" {
			return c.v
		}
		return Default
	}
	c.v, c.at = v, time.Now()
	return v
}

// Set zapamiętuje nowy język (po zapisie ustawienia).
func (c *Cache) Set(v string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.v, c.at = v, time.Now()
	c.mu.Unlock()
}
