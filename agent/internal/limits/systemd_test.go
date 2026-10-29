// SPDX-License-Identifier: AGPL-3.0-or-later

package limits

import (
	"slices"
	"testing"
)

func TestSystemdProperties(t *testing.T) {
	got := Properties(Limits{Priority: PriorityBelowNormal, CPUMaxPercent: 25, MemoryHardMB: 400}, 4)
	if !slices.Equal(got, []string{"CPUWeight=50", "IOWeight=50", "CPUQuota=100%", "MemoryMax=400M"}) {
		t.Fatal(got)
	}
	got = Properties(Limits{Priority: PriorityBackground}, 8)
	if !slices.Equal(got, []string{"CPUWeight=1", "IOWeight=1", "CPUQuota=", "MemoryMax=infinity"}) {
		t.Fatal(got)
	}
	if got := Properties(Limits{Priority: PriorityNormal, CPUMaxPercent: 0.01}, 1); got[2] != "CPUQuota=1%" {
		t.Fatal(got)
	}
}
