// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
	"time"
)

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for i := 1; i <= 100; i++ {
		h.observe(time.Duration(i) * time.Millisecond)
	}
	if p50 := h.quantile(0.5); p50 < 45*time.Millisecond || p50 > 56*time.Millisecond {
		t.Errorf("p50 = %v", p50)
	}
	if h.max() != 100*time.Millisecond {
		t.Errorf("max = %v", h.max())
	}
}
