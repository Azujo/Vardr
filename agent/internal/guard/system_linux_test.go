// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package guard

import (
	"testing"
	"time"
)

func TestParseBootTime(t *testing.T) {
	got := parseBootTime("cpu  1 2 3\nintr 5\nbtime 1793260800\nprocesses 9\n")
	if want := time.Unix(1793260800, 0).UTC(); !got.Equal(want) {
		t.Fatalf("boot time %v, want %v", got, want)
	}
	if !parseBootTime("cpu 1\n").IsZero() {
		t.Fatal("missing btime must give zero time")
	}
	if BootTime().IsZero() {
		t.Fatal("BootTime on this system is zero")
	}
}
