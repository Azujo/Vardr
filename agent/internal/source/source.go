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
	// Source: nazwa źródła w paczce (np. „syslog:udp”); puste = Event Log
	// („wineventlog:” + Channel).
	Source string
	// Peer: adres nadawcy (syslog).
	Peer string
	// Truncated: źródło przycięło treść (OriginalSize – rozmiar przed przycięciem).
	Truncated    bool
	OriginalSize int
}

// Position wskazuje ostatni rekord, po którym należy wznowić odczyt.
type Position struct {
	RecordID uint64
	Valid    bool
	// Oldest (gdy Valid=false): zacznij od najstarszego zdarzenia niezależnie
	// od ustawienia start_at – używane po utracie stanu agenta.
	Oldest bool
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
