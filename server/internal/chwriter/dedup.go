// SPDX-License-Identifier: AGPL-3.0-or-later

package chwriter

import "container/list"

// Seen to ograniczony zbiór ostatnio zapisanych identyfikatorów zdarzeń.
// Odfiltrowuje duplikaty przed zapisem (ponowione paczki, ponowne
// dostarczenie z kolejki). ReplacingMergeTree w ClickHouse usuwa resztę,
// ale dopiero przy scalaniu – detekcja nie może na tym polegać.
type Seen struct {
	max   int
	order *list.List
	set   map[string]*list.Element
}

// NewSeen tworzy zbiór pamiętający maksymalnie max identyfikatorów.
func NewSeen(max int) *Seen {
	return &Seen{max: max, order: list.New(), set: make(map[string]*list.Element, max)}
}

// Has sprawdza, czy identyfikator był już zapisany.
func (s *Seen) Has(id string) bool {
	_, ok := s.set[id]
	return ok
}

// Add dodaje identyfikator (po udanym zapisie), usuwając najstarsze ponad limit.
func (s *Seen) Add(id string) {
	if _, ok := s.set[id]; ok {
		return
	}
	s.set[id] = s.order.PushBack(id)
	for s.order.Len() > s.max {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.set, oldest.Value.(string))
	}
}

// Len zwraca liczbę zapamiętanych identyfikatorów.
func (s *Seen) Len() int { return s.order.Len() }
