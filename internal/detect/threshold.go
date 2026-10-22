// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strings"
	"time"
)

// Semantyka reguł progowych (vardr.threshold) – wspólna dla silnika
// w locie, silnika zapytań i testu reguły w panelu, niezależna od
// kolejności napływu zdarzeń:
//
//  1. Okno spełniające próg: przedział [s, s+Window] (czas zdarzenia), w którym
//     jest co najmniej Count pasujących zdarzeń – albo Count różnych wartości
//     pola Distinct – z tym samym kluczem GroupBy.
//  2. Do alertu należą zdarzenia z okien spełniających próg oraz – łańcuchowo –
//     zdarzenia tego klucza odległe od należących o najwyżej Suppress
//     (atak trwa dalej). Suppress jest zawsze ≥ Window. Zdarzenia, które już
//     są w alercie (seed), też zaczepiają łańcuch.
//  3. Ciągła seria takich zdarzeń to jeden alert.

// Span to przedział indeksów [From, To) w posortowanych zdarzeniach.
type Span struct{ From, To int }

// Series opisuje posortowane po czasie zdarzenia jednego klucza.
type Series interface {
	Len() int
	Time(i int) time.Time
	Value(i int) string // wartość pola Distinct
	Seed(i int) bool    // zdarzenie już w alercie
}

// ThresholdMarks wyznacza zdarzenia należące do alertów (punkty 1–2) i okna
// spełniające próg. Zwraca też, czy cokolwiek należy.
func ThresholdMarks(s Series, th *Threshold, suppress time.Duration) ([]bool, []Span, bool) {
	n := s.Len()
	marks := make([]bool, n)
	seeded := false
	for i := range n {
		if s.Seed(i) {
			marks[i], seeded = true, true
		}
	}
	w := time.Duration(th.Window)
	diff := make([]int, n+1)
	var wins []Span
	counts := map[string]int{}
	j, lastTo := 0, 0
	for i := 0; n >= th.Count && i < n; i++ {
		end := s.Time(i).Add(w)
		for j < n && !s.Time(j).After(end) {
			counts[s.Value(j)]++
			j++
		}
		if i > 0 {
			if v := s.Value(i - 1); counts[v] > 1 {
				counts[v]--
			} else {
				delete(counts, v)
			}
		}
		ok := j-i >= th.Count
		if ok && th.Distinct != "" {
			ok = len(counts) >= th.Count
		}
		if !ok {
			continue
		}
		diff[i]++
		diff[j]--
		if j > lastTo { // okno nie zawiera się w poprzednim
			wins = append(wins, Span{i, j})
			lastTo = j
		}
	}
	if len(wins) == 0 && !seeded {
		return marks, nil, false
	}
	run := 0
	for i := range n {
		run += diff[i]
		marks[i] = marks[i] || run > 0
	}
	// Łańcuch: w przód i wstecz od zdarzeń należących do alertu.
	var last time.Time
	have := false
	for i := range n {
		t := s.Time(i)
		if marks[i] || (have && t.Sub(last) <= suppress) {
			marks[i], last, have = true, t, true
		}
	}
	have = false
	for i := n - 1; i >= 0; i-- {
		t := s.Time(i)
		if marks[i] || (have && last.Sub(t) <= suppress) {
			marks[i], last, have = true, t, true
		}
	}
	return marks, wins, true
}

// Components dzieli zaznaczone zdarzenia na ciągłe serie (alerty).
func Components(s Series, marks []bool, suppress time.Duration) []Span {
	var out []Span
	for i := range marks {
		if !marks[i] {
			continue
		}
		if k := len(out) - 1; k >= 0 && out[k].To == i && s.Time(i).Sub(s.Time(i-1)) <= suppress {
			out[k].To = i + 1
			continue
		}
		out = append(out, Span{i, i + 1})
	}
	return out
}

// DistinctValue: wartość pola Distinct zdarzenia małymi literami (puste
// albo „-” – „(brak)”); bez Distinct – pusta.
func (r *Rule) DistinctValue(e Event) string {
	if r.Vardr.Threshold == nil || r.Vardr.Threshold.Distinct == "" {
		return ""
	}
	v, _ := e.Get(r.Vardr.Threshold.Distinct)
	if v = strings.ToLower(v); v == "" || v == "-" {
		return "(brak)"
	}
	return v
}
