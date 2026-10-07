// Package throttle to prosty ogranicznik tempa (token bucket) używany do
// limitu zdarzeń na sekundę i limitu przepustowości wysyłki.
package throttle

import (
	"context"
	"sync"
	"time"
)

// Limiter ogranicza tempo do rate jednostek na sekundę, z zapasem burst.
// Pobranie większej liczby jednostek niż burst jest dozwolone – limiter
// „zadłuża się” i odpowiednio dłużej czeka (potrzebne dla dużych paczek).
// Zerowy lub nil Limiter nie ogranicza niczego.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time

	waited time.Duration // łączny czas oczekiwania (do statystyk)
}

// New tworzy limiter. rate <= 0 oznacza brak limitu (zwraca nil).
func New(rate float64, burst float64) *Limiter {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: burst, tokens: burst, now: time.Now}
}

// Wait pobiera n jednostek, czekając, jeśli to potrzebne.
func (l *Limiter) Wait(ctx context.Context, n int) error {
	if l == nil || n <= 0 {
		return nil
	}
	l.mu.Lock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = now
	l.tokens -= float64(n)
	var wait time.Duration
	if l.tokens < 0 {
		wait = time.Duration(-l.tokens / l.rate * float64(time.Second))
		l.waited += wait
	}
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Allow pobiera n jednostek bez czekania; false, gdy jest ich za mało
// (wtedy nic nie jest pobierane). nil = brak limitu.
func (l *Limiter) Allow(n int) bool {
	if l == nil || n <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = now
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}

// Waited zwraca łączny czas spędzony na dławieniu.
func (l *Limiter) Waited() time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waited
}
