// SPDX-License-Identifier: AGPL-3.0-or-later

package bus

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestGzipRoundTripConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				in := []byte(strings.Repeat("zdarzenie ", 10+g*i%300))
				gz, err := Gzip(in)
				if err != nil {
					t.Error(err)
					return
				}
				out, err := Gunzip(gz, 1<<20)
				if err != nil || !bytes.Equal(in, out) {
					t.Errorf("różnica po rozpakowaniu: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestGunzipLimitAndGarbage(t *testing.T) {
	gz, _ := Gzip(bytes.Repeat([]byte("a"), 10000))
	if _, err := Gunzip(gz, 100); err == nil {
		t.Fatal("limit rozmiaru nie zadziałał")
	}
	if _, err := Gunzip([]byte("to nie gzip"), 100); err == nil {
		t.Fatal("śmieci powinny dać błąd")
	}
	// Pula po błędzie nadal działa.
	if out, err := Gunzip(gz, 1<<20); err != nil || len(out) != 10000 {
		t.Fatalf("%d %v", len(out), err)
	}
}
