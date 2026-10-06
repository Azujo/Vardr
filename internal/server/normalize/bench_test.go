package normalize

import (
	"testing"

	"siem/internal/contract"
)

// Koszt normalizacji jednego zdarzenia (jeden rdzeń). Przy docelowych
// 10 000 zdarzeń/s budżet to 100 µs na zdarzenie na rdzeń.
func BenchmarkSecurity4625(b *testing.B) {
	e := contract.Event{ID: "agt-1:Security:g0:1", Source: "wineventlog:Security", Raw: sec4625}
	b.SetBytes(int64(len(sec4625)))
	for b.Loop() {
		if _, err := Event(e, "agt-1", ingested); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSystem7045(b *testing.B) {
	e := contract.Event{ID: "agt-1:System:g0:1", Source: "wineventlog:System", Raw: sys7045}
	b.SetBytes(int64(len(sys7045)))
	for b.Loop() {
		if _, err := Event(e, "agt-1", ingested); err != nil {
			b.Fatal(err)
		}
	}
}
