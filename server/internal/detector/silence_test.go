// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"strings"
	"testing"
	"time"
)

func hoursUntil(end time.Time, n int, every time.Duration) []time.Time {
	var out []time.Time
	for i := n - 1; i >= 0; i-- {
		out = append(out, end.Add(-time.Duration(i)*every).Truncate(time.Hour))
	}
	return out
}

func TestSilenceCheck(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	// Zapora nadaje co godzinę – próg 2 h.
	fw := Source{Agent: "agt-col", Host: "fw1", Last: now.Add(-3 * time.Hour), Hours: hoursUntil(now.Add(-3*time.Hour), 100, time.Hour)}
	fwOK := fw
	fwOK.Host, fwOK.Last = "fw2", now.Add(-90*time.Minute)
	// Router cichy nocami (przerwy 10 h) – 4 h ciszy to norma, 13,5 h – nie.
	var nightly []time.Time
	for d := 6; d >= 0; d-- {
		for h := 8; h <= 22; h++ {
			nightly = append(nightly, time.Date(2026, 10, 10+d, h, 0, 0, 0, time.UTC))
		}
	}
	rt := Source{Agent: "agt-col", Host: "mikrotik", Last: now.Add(-4 * time.Hour), Hours: nightly}
	rtLong := rt
	rtLong.Host, rtLong.Last = "mikrotik2", time.Date(2026, 10, 16, 22, 30, 0, 0, time.UTC) // 13,5 h > 10 h + 1 h
	// Źródło rzadkie – pomijane.
	rare := Source{Agent: "agt-col", Host: "ups", Last: now.Add(-100 * time.Hour), Hours: hoursUntil(now.Add(-100*time.Hour), 10, 5*time.Hour)}
	// Chmura (bez komputera).
	cloud := Source{Agent: "agt-con", Dataset: "azure.signinlogs", Last: now.Add(-5 * time.Hour), Hours: hoursUntil(now.Add(-5*time.Hour), 50, time.Hour)}

	hits, back := SilenceCheck([]Source{fw, fwOK, rt, rtLong, rare, cloud}, now, time.Hour)
	var got []string
	for _, h := range hits {
		got = append(got, h.HostName+"|"+h.EventID)
	}
	if len(hits) != 3 || !strings.HasPrefix(got[0], "fw1|silent:agt-col/fw1/@") || !strings.HasPrefix(got[1], "mikrotik2|") ||
		!strings.HasPrefix(got[2], "|silent:agt-con//azure.signinlogs@") {
		t.Fatalf("alerty: %v", got)
	}
	if !strings.Contains(hits[0].Summary, "3 h") || !strings.Contains(hits[2].Summary, "źródło azure.signinlogs") {
		t.Fatalf("opis: %s / %s", hits[0].Summary, hits[2].Summary)
	}
	if len(back) != 2 || back[0] != fwOK.Key() || back[1] != rt.Key() {
		t.Fatalf("nadające: %v", back)
	}
	// Minimalny próg z konfiguracji.
	if hits, _ := SilenceCheck([]Source{fw}, now, 4*time.Hour); len(hits) != 0 {
		t.Fatalf("próg minimalny 4 h: %d alertów", len(hits))
	}
	if fmtSpan(26*time.Hour+13*time.Minute) != "26 h 13 min" || fmtSpan(50*time.Hour) != "2 dni 2 h" || fmtSpan(40*time.Minute) != "40 min" {
		t.Fatal("fmtSpan")
	}
}
