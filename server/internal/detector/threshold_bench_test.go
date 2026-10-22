// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"fmt"
	"testing"
	"time"

	"siem/internal/model"
)

// Zalew nieudanych logowań na jedno konto (brute force, 100/s) – koszt
// jednego zdarzenia, gdy alert progu już trwa.
func BenchmarkThresholdFlood(b *testing.B) {
	e := repoEngine(b)
	evs := make([]model.Event, b.N+5000)
	for i := range evs {
		evs[i] = failed(i, "jan", fmt.Sprintf("10.0.%d.%d", i/250%250, i%250), t0.Add(time.Duration(i)*10*time.Millisecond))
	}
	// Rozgrzewka: 5000 zdarzeń w pamięci klucza.
	for i := range 5000 {
		e.Evaluate(&model.Batch{Events: evs[i : i+1]})
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := range b.N {
		e.Evaluate(&model.Batch{Events: evs[5000+i : 5001+i]})
	}
}
