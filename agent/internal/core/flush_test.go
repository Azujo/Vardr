// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"testing"
	"time"

	"siem/internal/contract"
)

func TestFlushDue(t *testing.T) {
	a := &Agent{opts: Options{FlushInterval: 2 * time.Second, FlushMaxWait: 10 * time.Second, FlushMinEvents: 50}}
	b := &batcher{agent: a}
	if !b.due() {
		t.Fatal("pusta paczka (zapis pozycji) – od razu")
	}
	b.pending = make([]contract.Event, 3)
	b.firstAt = time.Now().Add(-3 * time.Second)
	if b.due() {
		t.Fatal("mała paczka sprzed 3 s powinna czekać")
	}
	b.firstAt = time.Now().Add(-9 * time.Second) // następny takt byłby po 11 s
	if !b.due() {
		t.Fatal("mała paczka po ~10 s – wysyłka")
	}
	b.firstAt = time.Now()
	b.pending = make([]contract.Event, 50)
	if !b.due() {
		t.Fatal("paczka od FlushMinEvents – co FlushInterval")
	}
	a.opts.FlushMaxWait = 0 // dawne zachowanie
	b.pending = make([]contract.Event, 1)
	if !b.due() {
		t.Fatal("bez FlushMaxWait – co FlushInterval")
	}
}
