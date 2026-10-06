// Package source definiuje wspólny interfejs źródeł logów agenta.
package source

import (
	"context"
	"time"
)

// Record to jedno zdarzenie odczytane ze źródła.
type Record struct {
	Channel    string
	RecordID   uint64
	EventID    uint32
	HasEventID bool
	CreatedAt  time.Time // czas wystąpienia zdarzenia wg źródła (zero, jeśli brak)
	Raw        string
	ReadAt     time.Time
}

// Position wskazuje ostatni rekord, po którym należy wznowić odczyt.
type Position struct {
	RecordID uint64
	Valid    bool
}

// Source to źródło logów (np. jeden kanał Event Log).
type Source interface {
	// Channel zwraca nazwę kanału / źródła.
	Channel() string
	// Run czyta zdarzenia od pozycji start i wysyła je do out, blokując się,
	// gdy odbiorca nie nadąża (backpressure). Zwraca pozycję ostatniego
	// wysłanego rekordu, żeby ponowne uruchomienie nie cofało odczytu.
	Run(ctx context.Context, start Position, out chan<- Record) (Position, error)
}
