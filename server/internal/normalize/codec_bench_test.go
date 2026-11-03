// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"siem/internal/model"
	"siem/server/internal/bus"
)

func report(b *testing.B, n int) {
	b.ReportAllocs()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n)/1000, "µs/zdarzenie")
}

// BenchmarkDecode: koszt zapisu i odczytu paczki między normalizatorem
// a odbiorcami SIEM_EVENTS (writer, detektor), JSON i format binarny.
func BenchmarkDecode(b *testing.B) {
	_, nb, err := Encoded(loadBatch(b), "agt-load-0001", time.Now(), 0, 16<<20)
	if err != nil {
		b.Fatal(err)
	}
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(nb); err != nil {
		b.Fatal(err)
	}
	bin := model.AppendBatch(nil, &nb)
	jsz, _ := bus.Gzip(js.Bytes())
	binz, _ := bus.Gzip(bin)
	b.Logf("JSON %d B (gzip %d), binarny %d B (gzip %d)", js.Len(), len(jsz), len(bin), len(binz))
	n := len(nb.Events)
	b.Run("json", func(b *testing.B) {
		for b.Loop() {
			var out model.Batch
			if err := json.Unmarshal(js.Bytes(), &out); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
	b.Run("binary", func(b *testing.B) {
		for b.Loop() {
			if _, err := model.DecodeBatch(bin); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
	b.Run("gunzip-json", func(b *testing.B) {
		for b.Loop() {
			if _, err := bus.Gunzip(jsz, 256<<20); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
	b.Run("gunzip-binary", func(b *testing.B) {
		for b.Loop() {
			if _, err := bus.Gunzip(binz, 256<<20); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
	b.Run("encode-json-gzip", func(b *testing.B) {
		for b.Loop() {
			var out bytes.Buffer
			enc := json.NewEncoder(&out)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(nb); err != nil {
				b.Fatal(err)
			}
			if _, err := bus.Gzip(out.Bytes()); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
	b.Run("encode-binary-gzip", func(b *testing.B) {
		for b.Loop() {
			if _, err := bus.Gzip(model.AppendBatch(nil, &nb)); err != nil {
				b.Fatal(err)
			}
		}
		report(b, n)
	})
}
