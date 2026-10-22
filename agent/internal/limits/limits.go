// SPDX-License-Identifier: AGPL-3.0-or-later

// Package limits nakłada na proces agenta ograniczenia zasobów („kaganiec”):
// priorytet CPU/I/O, twardy limit CPU, miękki i twardy limit pamięci.
package limits

import (
	"errors"
	"fmt"
	"math"
	"runtime/debug"
)

// Priorytety procesu.
const (
	PriorityNormal      = "normal"
	PriorityBelowNormal = "below_normal"
	// PriorityBackground (klasa IDLE) przydziela agentowi CPU tylko wtedy,
	// gdy nikt inny go nie potrzebuje. Na stale obciążonym komputerze agent
	// może nie nadążać – wtedy rośnie opóźnienie (ostrzeżenie w logu).
	PriorityBackground = "background"
)

// Limits to ustawienia kagańca.
type Limits struct {
	Priority      string  // normal | below_normal | background
	CPUMaxPercent float64 // twardy limit CPU w % całego komputera; 0 = brak
	MemorySoftMB  int     // miękki limit sterty Go (częstsze sprzątanie); 0 = brak
	MemoryHardMB  int     // twardy limit pamięci procesu (Job Object); 0 = brak
}

// Validate sprawdza poprawność ustawień.
func (l Limits) Validate() error {
	var errs []error
	switch l.Priority {
	case PriorityNormal, PriorityBelowNormal, PriorityBackground:
	default:
		errs = append(errs, fmt.Errorf("limits.priority: dozwolone %s, %s, %s", PriorityNormal, PriorityBelowNormal, PriorityBackground))
	}
	if l.CPUMaxPercent < 0 || l.CPUMaxPercent > 100 {
		errs = append(errs, errors.New("limits.cpu_max_percent musi być w zakresie 0–100"))
	}
	if l.CPUMaxPercent > 0 && l.CPUMaxPercent < 0.01 {
		errs = append(errs, errors.New("limits.cpu_max_percent: minimum to 0.01"))
	}
	if l.MemorySoftMB < 0 || (l.MemorySoftMB > 0 && l.MemorySoftMB < 16) {
		errs = append(errs, errors.New("limits.memory_soft_mb: 0 (brak) lub co najmniej 16"))
	}
	if l.MemoryHardMB < 0 || (l.MemoryHardMB > 0 && l.MemoryHardMB < 64) {
		errs = append(errs, errors.New("limits.memory_hard_mb: 0 (brak) lub co najmniej 64"))
	}
	if l.MemorySoftMB > 0 && l.MemoryHardMB > 0 && float64(l.MemoryHardMB) < 1.5*float64(l.MemorySoftMB) {
		errs = append(errs, errors.New("limits.memory_hard_mb musi wynosić co najmniej 1,5 × memory_soft_mb – twardy limit to bezpiecznik, nie punkt pracy"))
	}
	return errors.Join(errs...)
}

// applySoftMemory ustawia miękki limit pamięci środowiska Go. Po jego
// przekroczeniu GC pracuje częściej zamiast pozwalać stercie rosnąć.
func applySoftMemory(mb int) {
	if mb <= 0 {
		debug.SetMemoryLimit(math.MaxInt64)
		return
	}
	debug.SetMemoryLimit(int64(mb) << 20)
}
