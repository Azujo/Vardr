// SPDX-License-Identifier: AGPL-3.0-or-later

package throttle

import (
	"context"
	"testing"
	"time"
)

func TestNilLimiterNeverWaits(t *testing.T) {
	var l *Limiter = New(0, 0)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := l.Wait(context.Background(), 1000); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 50*time.Millisecond || l.Waited() != 0 {
		t.Fatal("brak limitu nie powinien spowalniać")
	}
}

func TestRateIsEnforced(t *testing.T) {
	l := New(1000, 100) // 1000/s, zapas 100
	start := time.Now()
	for i := 0; i < 400; i++ {
		_ = l.Wait(context.Background(), 1)
	}
	// 400 jednostek przy zapasie 100 => ~300 ms oczekiwania.
	if el := time.Since(start); el < 250*time.Millisecond || el > 600*time.Millisecond {
		t.Fatalf("400 jednostek przy 1000/s trwało %v, oczekiwano ~300 ms", el)
	}
}

func TestLargeRequestBorrows(t *testing.T) {
	l := New(10_000, 1000)
	start := time.Now()
	_ = l.Wait(context.Background(), 3000) // więcej niż zapas: dług 2000 => 200 ms
	if el := time.Since(start); el < 150*time.Millisecond || el > 400*time.Millisecond {
		t.Fatalf("pobranie ponad zapas trwało %v, oczekiwano ~200 ms", el)
	}
}

func TestWaitHonorsCancellation(t *testing.T) {
	l := New(1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = l.Wait(ctx, 1)
	if err := l.Wait(ctx, 10); err == nil {
		t.Fatal("oczekiwano anulowania")
	}
}

func TestAllowDoesNotWait(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(1, 3) // 1/s, zapas 3
	l.now = func() time.Time { return now }
	for i := range 3 {
		if !l.Allow(1) {
			t.Fatalf("próba %d powinna przejść", i+1)
		}
	}
	if l.Allow(1) {
		t.Fatal("czwarta próba bez czekania powinna zostać odrzucona")
	}
	now = now.Add(time.Second)
	if !l.Allow(1) || l.Allow(1) {
		t.Fatal("po sekundzie dokładnie jedna próba")
	}
	var nilLimiter *Limiter
	if !nilLimiter.Allow(100) {
		t.Fatal("brak limitu = zawsze wolno")
	}
}
