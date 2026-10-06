package winevt

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
	reRecordID = regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`)
	reEventID  = regexp.MustCompile(`<EventID(?:\s[^>]*)?>(\d+)</EventID>`)
)

// parseIDs wyciąga numer rekordu i Event ID z XML zdarzenia.
func parseIDs(xml string) (recordID uint64, eventID uint32, hasEventID bool, err error) {
	m := reRecordID.FindStringSubmatch(xml)
	if m == nil {
		return 0, 0, false, fmt.Errorf("brak EventRecordID w zdarzeniu")
	}
	recordID, err = strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, 0, false, err
	}
	if m := reEventID.FindStringSubmatch(xml); m != nil {
		v, err := strconv.ParseUint(m[1], 10, 32)
		if err == nil {
			return recordID, uint32(v), true, nil
		}
	}
	return recordID, 0, false, nil
}
