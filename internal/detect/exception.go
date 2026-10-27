// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"fmt"

	"siem/internal/lang"
)

// Wyjątki reguł (wersja 1.5.3): zdarzenia spełniające warunek wyjątku nie
// trafiają w regułę – typowo powtarzalny fałszywy alarm (konkretny komputer
// i proces). Warunek ma składnię selekcji Sigma (pole[|modyfikator] →
// wartość albo lista; wszystkie pola muszą pasować), a reguła po doklejeniu
// wyjątków to „warunek reguły i nie (wyjątek 1 albo wyjątek 2 …)” – ten sam
// węzeł w silniku strumieniowym i w SQL silnika zapytań.

// MaxExceptionFields: najwięcej pól w warunku wyjątku.
const MaxExceptionFields = 10

// Exception to wyjątek reguły.
type Exception struct {
	ID     int64
	RuleID string
	Match  map[string]any
}

// CompileException sprawdza i kompiluje warunek wyjątku.
func CompileException(m map[string]any) (Node, error) {
	switch {
	case len(m) == 0:
		return nil, lang.Errorf("wyjątek: pusty warunek", "exception: empty condition")
	case len(m) > MaxExceptionFields:
		return nil, lang.Errorf("wyjątek: najwyżej %d pól", "exception: at most %d fields", MaxExceptionFields)
	}
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			return nil, lang.Errorf("wyjątek: puste pole %s – pusty warunek pasowałby do zbyt wielu zdarzeń",
				"exception: empty value of %s – an empty condition would match too many events", k)
		}
	}
	return compileMap(m)
}

// ExceptionSQL zwraca warunek SQL wyjątku (sprawdzenie na historii w panelu).
func ExceptionSQL(m map[string]any) (string, error) {
	n, err := CompileException(m)
	if err != nil {
		return "", err
	}
	return n.sql(), nil
}

// ApplyExceptions dokleja wyjątki do reguł o pasujących id. Wyjątek, który
// się nie kompiluje, jest pomijany (błąd w wyniku) – reguła działa dalej bez
// niego, zamiast przestać wykrywać.
func ApplyExceptions(rules []*Rule, ex []Exception) []error {
	byRule := map[string][]Node{}
	var errs []error
	for _, e := range ex {
		n, err := CompileException(e.Match)
		if err != nil {
			errs = append(errs, fmt.Errorf("exception %d (%s): %w", e.ID, e.RuleID, err))
			continue
		}
		byRule[e.RuleID] = append(byRule[e.RuleID], n)
	}
	for _, r := range rules {
		if ns := byRule[r.ID]; len(ns) > 0 {
			r.match = and{r.match, not{or(ns)}}
			r.Exceptions = len(ns)
		}
	}
	return errs
}

// Suppressed zwraca kopię reguły, która trafia tylko w zdarzenia ukrywane
// przez wyjątek (warunek reguły i warunek wyjątku) – sprawdzenie na historii
// przed zapisem, ile i jakich trafień wyjątek wytnie.
func Suppressed(r *Rule, m map[string]any) (*Rule, error) {
	n, err := CompileException(m)
	if err != nil {
		return nil, err
	}
	c := *r
	c.match = and{r.match, n}
	return &c, nil
}
