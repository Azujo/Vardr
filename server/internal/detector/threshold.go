package detector

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"siem/internal/alerts"
	"siem/server/internal/detect"
)

// Reguły progowe (heimdall.threshold).
//
// Semantyka (ta sama obowiązuje silnik zapytań, etap 4d): alert powstaje,
// gdy w dowolnym oknie długości Window – liczonym po czasie zdarzenia – jest
// co najmniej Count pasujących zdarzeń (albo Count różnych wartości pola
// Distinct) z tym samym kluczem GroupBy. Do alertu trafiają wszystkie
// zdarzenia z tego okna, a kolejne zdarzenia tego klucza są dopisywane do
// alertu, dopóki przerwa między nimi nie przekroczy Suppress.
//
// Stan (zdarzenia z ostatniego okna) jest w pamięci i – w tej samej
// transakcji co alerty – w tabeli gjallarhorn.threshold_events, więc
// restart detektora go nie gubi. Zdarzenie spóźnione o więcej niż
// ThresholdLateness względem najnowszego zdarzenia klucza jest liczone
// tylko z tym, co zostało w oknie (silnik zapytań nadrobi takie przypadki).

// ThresholdLateness: jak długo trzymać zdarzenia ponad okno progu
// (spóźnione zdarzenia, np. z bufora agenta po przerwie w łączności).
const ThresholdLateness = time.Hour

// Limity pamięci stanu progów.
const (
	maxEntriesPerKey = 20000
	maxKeysPerRule   = 50000
)

type entry struct {
	alerts.Observation
	emitted bool // zdarzenie dopisane już do alertu
}

type keyState struct {
	entries []*entry // posortowane po czasie zdarzenia
	ids     map[string]bool
	fields  map[string]string
	// Okres (czas zdarzeń) bieżącego alertu; zero = próg nieprzekroczony.
	firedFrom, firedTo time.Time
	summary, instr     string
	seen               time.Time // zegar ścienny – do usuwania nieaktywnych kluczy
}

type ruleState struct {
	sig  string
	keys map[string]*keyState
}

// Thresholds to stan reguł progowych.
type Thresholds struct {
	mu      sync.Mutex
	rules   map[string]*ruleState
	now     func() time.Time
	dropped int // zdarzenia odrzucone przez limity pamięci
}

// NewThresholds tworzy pusty stan.
func NewThresholds() *Thresholds {
	return &Thresholds{rules: map[string]*ruleState{}, now: time.Now}
}

// Signature opisuje parametry reguły, od których zależy stan progu
// (zmiana = stan od nowa).
func Signature(r *detect.Rule) string {
	t := r.Heimdall.Threshold
	if t == nil {
		return ""
	}
	return fmt.Sprintf("%d|%s|%s|%s", t.Count, time.Duration(t.Window), strings.ToLower(t.Distinct),
		strings.Join(r.Heimdall.GroupBy, ","))
}

// sync dopasowuje stan do bieżących reguł progowych.
func (t *Thresholds) sync(rules []*detect.Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keep := map[string]bool{}
	for _, r := range rules {
		if !r.IsThreshold() {
			continue
		}
		sig := Signature(r)
		keep[r.ID] = true
		if rs := t.rules[r.ID]; rs == nil || rs.sig != sig {
			t.rules[r.ID] = &ruleState{sig: sig, keys: map[string]*keyState{}}
		}
	}
	for id := range t.rules {
		if !keep[id] {
			delete(t.rules, id)
		}
	}
}

// Restore wczytuje stan zapisany w bazie (po starcie albo po nieudanym
// zapisie – pamięć wraca wtedy do stanu z ostatniej udanej transakcji).
func (t *Thresholds) Restore(rules []*detect.Rule, obs []alerts.Observation) int {
	t.mu.Lock()
	t.rules = map[string]*ruleState{}
	t.mu.Unlock()
	t.sync(rules)
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, o := range obs {
		rs := t.rules[o.RuleID]
		if rs == nil || rs.sig != o.Sig {
			continue
		}
		ks := rs.key(o.GroupKey, o.GroupFields, t.now())
		if ks.ids[o.EventID] {
			continue
		}
		ks.insert(&entry{Observation: o})
		n++
	}
	return n
}

func (rs *ruleState) key(k string, fields map[string]string, now time.Time) *keyState {
	ks := rs.keys[k]
	if ks == nil {
		ks = &keyState{ids: map[string]bool{}, fields: fields}
		rs.keys[k] = ks
	}
	ks.seen = now
	return ks
}

func (ks *keyState) insert(e *entry) {
	i := sort.Search(len(ks.entries), func(i int) bool { return ks.entries[i].EventTime.After(e.EventTime) })
	ks.entries = append(ks.entries, nil)
	copy(ks.entries[i+1:], ks.entries[i:])
	ks.entries[i] = e
	ks.ids[e.EventID] = true
}

// prune usuwa zdarzenia starsze niż najnowsze − okno − spóźnienie
// i najstarsze ponad limit.
func (ks *keyState) prune(window time.Duration) {
	if len(ks.entries) == 0 {
		return
	}
	cut := ks.entries[len(ks.entries)-1].EventTime.Add(-window - ThresholdLateness)
	n := sort.Search(len(ks.entries), func(i int) bool { return !ks.entries[i].EventTime.Before(cut) })
	if over := len(ks.entries) - maxEntriesPerKey; over > n {
		n = over
	}
	for _, e := range ks.entries[:n] {
		delete(ks.ids, e.EventID)
	}
	ks.entries = append(ks.entries[:0:0], ks.entries[n:]...)
}

// observe przyjmuje pasujące zdarzenie reguły progowej. Zwraca obserwację
// do zapisu (nil = zdarzenie już znane) i trafienia, gdy próg jest
// przekroczony (albo alert progu trwa).
func (t *Thresholds) observe(r *detect.Rule, ev detect.Event, base alerts.Hit) (*alerts.Observation, []alerts.Hit) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rs := t.rules[r.ID]
	if rs == nil {
		return nil, nil
	}
	th := r.Heimdall.Threshold
	window, suppress := time.Duration(th.Window), time.Duration(r.Heimdall.Suppress)
	if _, ok := rs.keys[base.GroupKey]; !ok && len(rs.keys) >= maxKeysPerRule {
		t.dropped++
		return nil, nil
	}
	ks := rs.key(base.GroupKey, base.GroupFields, t.now())
	if ks.ids[base.EventID] {
		return nil, nil
	}
	o := alerts.Observation{RuleID: r.ID, Sig: rs.sig, GroupKey: base.GroupKey, GroupFields: base.GroupFields,
		EventID: base.EventID, EventTime: base.EventTime, AgentID: base.AgentID, HostName: base.HostName,
		UserName: base.UserName, SourceIP: base.SourceIP, ExpiresAt: t.now().Add(window + ThresholdLateness)}
	if th.Distinct != "" {
		v, _ := ev.Get(th.Distinct)
		if v = strings.ToLower(v); v == "" || v == "-" {
			v = "(brak)"
		}
		o.Value = v
	}
	e := &entry{Observation: o}
	ks.insert(e)
	defer ks.prune(window)

	at := e.EventTime
	// Alert progu trwa: zdarzenie dopisywane bez ponownego liczenia.
	if !ks.firedFrom.IsZero() && !at.Before(ks.firedFrom.Add(-suppress)) && !at.After(ks.firedTo.Add(suppress)) {
		if at.After(ks.firedTo) {
			ks.firedTo = at
		}
		if at.Before(ks.firedFrom) {
			ks.firedFrom = at
		}
		e.emitted = true
		return &o, []alerts.Hit{t.hit(base, o, ks)}
	}
	win := ks.window(at, window, th)
	if win == nil {
		return &o, nil
	}
	ks.firedFrom, ks.firedTo = win[0].EventTime, win[len(win)-1].EventTime
	ks.summary, ks.instr = thresholdTexts(r, ev, win)
	var hits []alerts.Hit
	for _, w := range win {
		if !w.emitted {
			w.emitted = true
			hits = append(hits, t.hit(base, w.Observation, ks))
		}
	}
	return &o, hits
}

func (t *Thresholds) hit(base alerts.Hit, o alerts.Observation, ks *keyState) alerts.Hit {
	h := base
	h.EventID, h.EventTime, h.AgentID, h.HostName, h.UserName, h.SourceIP =
		o.EventID, o.EventTime, o.AgentID, o.HostName, o.UserName, o.SourceIP
	h.Summary, h.Instructions = ks.summary, ks.instr
	return h
}

// window szuka okna długości w, które zawiera zdarzenie z czasu at i ma
// co najmniej Count zdarzeń (różnych wartości). Zwraca zdarzenia okna.
func (ks *keyState) window(at time.Time, w time.Duration, th *detect.Threshold) []*entry {
	es := ks.entries
	lo := sort.Search(len(es), func(i int) bool { return !es[i].EventTime.Before(at.Add(-w)) })
	hi := sort.Search(len(es), func(i int) bool { return es[i].EventTime.After(at.Add(w)) })
	if hi-lo < th.Count {
		return nil
	}
	if th.Distinct != "" && distinct(es[lo:hi]) < th.Count {
		return nil
	}
	// Okna [s, s+w] o początku w zdarzeniu z przedziału [at−w, at].
	j := lo
	counts := map[string]int{}
	for i := lo; i < hi && !es[i].EventTime.After(at); i++ {
		end := es[i].EventTime.Add(w)
		for j < hi && !es[j].EventTime.After(end) {
			counts[es[j].Value]++
			j++
		}
		if i > lo {
			if v := es[i-1].Value; counts[v] > 1 {
				counts[v]--
			} else {
				delete(counts, v)
			}
		}
		if j-i < th.Count {
			continue
		}
		// Okno [s, s+w] zawiera bieżące zdarzenie, bo s ≥ at−w.
		if th.Distinct == "" || len(counts) >= th.Count {
			return es[i:j]
		}
	}
	return nil
}

// fmtWindow: czas okna po polsku („5 min”, „1 h”, „90 s”).
func fmtWindow(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%d min", d/time.Minute)
	}
	return fmt.Sprintf("%d s", d/time.Second)
}

func distinct(es []*entry) int {
	seen := map[string]bool{}
	for _, e := range es {
		seen[e.Value] = true
	}
	return len(seen)
}

// thresholdTexts: opis i instrukcja alertu progowego (zmienne {{count}},
// {{window}} i {{values}} – lista różnych wartości pola Distinct).
func thresholdTexts(r *detect.Rule, ev detect.Event, win []*entry) (string, string) {
	th := r.Heimdall.Threshold
	window := fmtWindow(time.Duration(th.Window))
	var key []string
	for _, f := range r.Heimdall.GroupBy {
		if v, _ := ev.Get(f); v != "" {
			key = append(key, f+"="+v)
		}
	}
	extra := map[string]string{"count": fmt.Sprint(len(win)), "window": window}
	var s string
	if th.Distinct != "" {
		var vals []string
		seen := map[string]bool{}
		for _, e := range win {
			if !seen[e.Value] {
				seen[e.Value] = true
				vals = append(vals, e.Value)
			}
		}
		extra["count"] = fmt.Sprint(len(vals))
		list := vals
		if len(list) > 10 {
			list = append(list[:10:10], fmt.Sprintf("… (+%d)", len(vals)-10))
		}
		extra["values"] = strings.Join(list, ", ")
		s = fmt.Sprintf("próg: %d różnych %s w %s (%d zdarzeń)", len(vals), th.Distinct, window, len(win))
	} else {
		extra["values"] = ""
		s = fmt.Sprintf("próg: %d zdarzeń w %s", len(win), window)
	}
	if len(key) > 0 {
		s += ", " + strings.Join(key, ", ")
	}
	if th.Distinct != "" {
		s += "; " + th.Distinct + ": " + extra["values"]
	}
	return s, detect.RenderWith(r.Heimdall.Instructions, ev, extra)
}

// Sweep usuwa klucze bez zdarzeń dłużej niż okno + łączenie + spóźnienie.
// Zwraca liczbę kluczy w pamięci i zdarzeń odrzuconych przez limity.
func (t *Thresholds) Sweep(rules []*detect.Rule) (keys, dropped int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, r := range rules {
		rs := t.rules[r.ID]
		if rs == nil {
			continue
		}
		idle := time.Duration(r.Heimdall.Threshold.Window) + time.Duration(r.Heimdall.Suppress) + ThresholdLateness
		for k, ks := range rs.keys {
			if now.Sub(ks.seen) > idle {
				delete(rs.keys, k)
			}
		}
		keys += len(rs.keys)
	}
	dropped, t.dropped = t.dropped, 0
	return keys, dropped
}
