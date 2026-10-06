package loadgen

import (
	"testing"
	"time"

	"siem/internal/contract"
	"siem/internal/server/normalize"
)

// Wygenerowane zdarzenia muszą przechodzić przez prawdziwy normalizator –
// inaczej test obciążenia mierzyłby ścieżkę kwarantanny zamiast typowej.
func TestGeneratedEventsNormalize(t *testing.T) {
	now := time.Now().UTC()
	for i, m := range mix {
		ch, raw := m.gen("LOAD-0001", uint64(i+1), now.Format("2006-01-02T15:04:05.0000000Z"))
		e, err := normalize.Event(contract.Event{ID: "agt-load-0001:" + ch + ":g1:1", Source: "wineventlog:" + ch, Raw: raw},
			"agt-load-0001", now)
		if err != nil {
			t.Fatalf("szablon %d (%s): %v\n%s", i, ch, err, raw)
		}
		if e.HostName != "load-0001.lab.local" || e.Code == 0 || e.TimeQuality != "" || (e.Action == "" && ch != "Application") {
			t.Errorf("szablon %d: %+v", i, e)
		}
	}
}
