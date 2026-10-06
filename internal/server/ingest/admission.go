package ingest

import (
	"context"
	"log/slog"
	"math"
	"sync/atomic"
	"time"
)

// Admission decyduje, czy przyjąć kolejną paczkę, ZANIM zostanie odczytana
// jej treść (pierwsza warstwa obrony przed przeciążeniem, roadmapa
// załącznik E). Odmowa kosztuje serwer prawie nic, a dane czekają u agenta.
type Admission struct {
	// MaxInFlight ogranicza liczbę paczek obsługiwanych jednocześnie
	// (pamięć: każda to do MaxCompressed+MaxDecompressed bajtów). 0 = bez limitu.
	MaxInFlight int
	// HighWater to zajętość kolejki (0–1), od której paczki są odrzucane.
	HighWater float64

	slots    chan struct{}
	fill     atomic.Uint64 // math.Float64bits zajętości kolejki
	inFlight atomic.Int64
}

// NewAdmission tworzy kontrolę przyjęć.
func NewAdmission(maxInFlight int, highWater float64) *Admission {
	a := &Admission{MaxInFlight: maxInFlight, HighWater: highWater}
	if maxInFlight > 0 {
		a.slots = make(chan struct{}, maxInFlight)
	}
	return a
}

// Verdict to wynik kontroli przyjęcia.
type Verdict int

const (
	Admit     Verdict = iota
	Busy              // za dużo równoległych paczek → 429
	QueueFull         // kolejka prawie pełna → 503
)

// Acquire rezerwuje miejsce; przy Admit wywołujący musi wywołać Release.
func (a *Admission) Acquire() Verdict {
	if a == nil {
		return Admit
	}
	if a.HighWater > 0 && a.Fill() >= a.HighWater {
		return QueueFull
	}
	if a.slots != nil {
		select {
		case a.slots <- struct{}{}:
		default:
			return Busy
		}
	}
	a.inFlight.Add(1)
	return Admit
}

// Release zwalnia miejsce zajęte przez Acquire.
func (a *Admission) Release() {
	if a == nil {
		return
	}
	a.inFlight.Add(-1)
	if a.slots != nil {
		<-a.slots
	}
}

// InFlight zwraca liczbę paczek w trakcie obsługi.
func (a *Admission) InFlight() int64 {
	if a == nil {
		return 0
	}
	return a.inFlight.Load()
}

// Fill zwraca ostatnio zmierzoną zajętość kolejki (0–1).
func (a *Admission) Fill() float64 {
	if a == nil {
		return 0
	}
	return math.Float64frombits(a.fill.Load())
}

// SetFill zapisuje zmierzoną zajętość kolejki.
func (a *Admission) SetFill(f float64) {
	if a != nil {
		a.fill.Store(math.Float64bits(f))
	}
}

// WatchFill co interval mierzy zajętość kolejki funkcją measure. Błąd
// pomiaru nie blokuje przyjęć (o niedostępności NATS i tak powie publikacja).
func (a *Admission) WatchFill(ctx context.Context, log *slog.Logger, interval time.Duration, measure func(context.Context) (float64, error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	full := false
	for {
		mctx, cancel := context.WithTimeout(ctx, interval)
		f, err := measure(mctx)
		cancel()
		if err == nil {
			a.SetFill(f)
			switch {
			case f >= a.HighWater && !full:
				full = true
				log.Error("kolejka prawie pełna – odrzucam nowe paczki (agenci buforują u siebie)", "fill", f, "high_water", a.HighWater)
			case f < a.HighWater && full:
				full = false
				log.Info("kolejka odblokowana – przyjmuję paczki", "fill", f)
			}
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}
