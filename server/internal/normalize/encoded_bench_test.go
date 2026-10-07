package normalize

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/server/internal/loadgen"
)

// loadBatch buduje skompresowaną paczkę 500 zdarzeń z mieszanki generatora.
func loadBatch(b *testing.B) []byte {
	now := time.Now().UTC()
	batch := contract.Batch{Schema: contract.SchemaBatchV1, BatchID: contract.NewBatchID(), AgentID: "agt-load-0001", SentAt: now}
	for i := range 500 {
		ch, raw := loadgen.RandomEvent("LOAD-0001", uint64(i+1), now)
		batch.Events = append(batch.Events, contract.Event{ID: fmt.Sprintf("agt-load-0001:%s:g1:%d", ch, i+1),
			Source: "wineventlog:" + ch, ReadAt: now, Raw: raw})
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false) // jak agent
	if err := enc.Encode(batch); err != nil {
		b.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

// BenchmarkEncoded mierzy całą ścieżkę paczki (bez NATS); ns/op dzielone
// przez 500 to koszt jednego zdarzenia.
func BenchmarkEncoded(b *testing.B) {
	gz := loadBatch(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Encoded(gz, "agt-load-0001", time.Now(), 16<<20); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/500/1000, "µs/zdarzenie")
}
