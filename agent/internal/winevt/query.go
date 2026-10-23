// SPDX-License-Identifier: AGPL-3.0-or-later

package winevt

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxQueryTerms to maksymalna liczba warunków w zapytaniu XPath przekazywanym
// do Event Log. Pomiar na Windows 11 24H2: 23 warunki działają, 24 są
// odrzucane (zakres "EventID>=a and EventID<=b" liczy się jako jeden warunek).
// Zostawiamy margines; przy dłuższych listach filtrujemy po stronie agenta.
const MaxQueryTerms = 20

// BuildQuery tworzy zapytanie XPath dla listy Event ID. Kolejne numery są
// łączone w zakresy. Zwraca agentSide=true, gdy lista jest zbyt długa
// i filtr musi zostać zastosowany w agencie (zapytanie obejmuje wtedy wszystko).
func BuildQuery(ids []uint32) (query string, agentSide bool) {
	if len(ids) == 0 {
		return "*", false
	}
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	var terms []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if j > i {
			terms = append(terms, fmt.Sprintf("(EventID>=%d and EventID<=%d)", sorted[i], sorted[j]))
		} else {
			terms = append(terms, fmt.Sprintf("EventID=%d", sorted[i]))
		}
		i = j + 1
	}
	if len(terms) > MaxQueryTerms {
		return "*", true
	}
	return "*[System[(" + strings.Join(terms, " or ") + ")]]", false
}

var (
	reRecordID    = regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`)
	reEventID     = regexp.MustCompile(`<EventID(?:\s[^>]*)?>(\d+)</EventID>`)
	reTimeCreated = regexp.MustCompile(`<TimeCreated SystemTime=['"]([^'"]+)['"]`)
)

// eventMeta to pola potrzebne agentowi; pełne parsowanie robi serwer.
type eventMeta struct {
	RecordID   uint64
	EventID    uint32
	HasEventID bool
	CreatedAt  time.Time // zero, jeśli brak
}

// parseMeta wyciąga numer rekordu, Event ID i czas utworzenia z XML zdarzenia.
func parseMeta(xml string) (eventMeta, error) {
	var m eventMeta
	r := reRecordID.FindStringSubmatch(xml)
	if r == nil {
		return m, fmt.Errorf("no EventRecordID in the event")
	}
	id, err := strconv.ParseUint(r[1], 10, 64)
	if err != nil {
		return m, err
	}
	m.RecordID = id
	if e := reEventID.FindStringSubmatch(xml); e != nil {
		if v, err := strconv.ParseUint(e[1], 10, 32); err == nil {
			m.EventID, m.HasEventID = uint32(v), true
		}
	}
	if t := reTimeCreated.FindStringSubmatch(xml); t != nil {
		if ts, err := time.Parse(time.RFC3339Nano, t[1]); err == nil {
			m.CreatedAt = ts
		}
	}
	return m, nil
}
