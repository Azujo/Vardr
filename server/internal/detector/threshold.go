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
// Semantyka – wspólna dla obu silników (w locie i zapytań), niezależna od
// kolejności napływu zdarzeń:
//
//  1. Okno spełniające próg: przedział [s, s+Window] (czas zdarzenia), w którym
//     jest co najmniej Count pasujących zdarzeń – albo Count różnych wartości
//     pola Distinct – z tym samym kluczem GroupBy.
//  2. Do alertu należą zdarzenia z okien spełniających próg oraz – łańcuchowo –
//     zdarzenia tego klucza odległe od należących o najwyżej Suppress
//     (atak trwa dalej). Suppress jest zawsze ≥ Window. Zdarzenia, które już
//     są w alercie (emitted), też zaczepiają łańcuch – nawet gdy okno, które
//     je tam wprowadziło, wypadło już z pamięci albo z zakresu zapytania.
//  3. Ciągła seria takich zdarzeń to jeden alert (łączenie w Record).
//
// Silnik w locie trzyma zdarzenia z ostatnich Window + max(Suppress,
// ThresholdLateness) w pamięci i – w tej samej transakcji co alerty –
// w tabeli gjallarhorn.threshold_events, więc restart detektora ich nie gubi.
// Silnik zapytań liczy to samo na zdarzeniach z ClickHouse (kontekst ±
// Window+Suppress wokół nowych zdarzeń).

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

// span to przedział indeksów [from, to) w posortowanych zdarzeniach.
type span struct{ from, to int }

// thresholdMarks wyznacza zdarzenia należące do alertów (punkty 1–2
// semantyki) i okna spełniające próg. Zdarzenia muszą być posortowane po
// czasie; wartość pola Distinct w Value. Zwraca też, czy cokolwiek należy.
func thresholdMarks(es []*entry, th *detect.Threshold, suppress time.Duration) ([]bool, []span, bool) {
	n := len(es)
	marks := make([]bool, n)
	seeded := false
	for i, e := range es {
		if e.emitted {
			marks[i], seeded = true, true
		}
	}
	w := time.Duration(th.Window)
	diff := make([]int, n+1)
	var wins []span
	counts := map[string]int{}
	j, lastTo := 0, 0
	for i := 0; i < n; i++ {
		end := es[i].EventTime.Add(w)
		for j < n && !es[j].EventTime.After(end) {
			counts[es[j].Value]++
			j++
		}
		if i > 0 {
			if v := es[i-1].Value; counts[v] > 1 {
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
			wins = append(wins, span{i, j})
			lastTo = j
		}
	}
	if len(wins) == 0 && !seeded {
		return marks, nil, false
	}
	run := 0
	for i := 0; i < n; i++ {
		run += diff[i]
		marks[i] = marks[i] || run > 0
	}
	// Łańcuch: w przód i wstecz od zdarzeń należących do alertu.
	var last time.Time
	have := false
	for i := 0; i < n; i++ {
		t := es[i].EventTime
		if marks[i] || (have && t.Sub(last) <= suppress) {
			marks[i], last, have = true, t, true
		}
	}
	have = false
	for i := n - 1; i >= 0; i-- {
		t := es[i].EventTime
		if marks[i] || (have && last.Sub(t) <= suppress) {
			marks[i], last, have = true, t, true
		}
	}
	return marks, wins, true
}

// components dzieli zaznaczone zdarzenia na ciągłe serie (przyszłe alerty).
func components(es []*entry, marks []bool, suppress time.Duration) []span {
	var out []span
	for i := 0; i < len(es); i++ {
		if !marks[i] {
			continue
		}
		if k := len(out) - 1; k >= 0 && out[k].to == i && es[i].EventTime.Sub(es[i-1].EventTime) <= suppress {
			out[k].to = i + 1
			continue
		}
		out = append(out, span{i, i + 1})
	}
	return out
}

type keyState struct {
	entries []*entry // posortowane po czasie zdarzenia
	ids     map[string]bool
	fields  map[string]string
	seen    time.Time // zegar ścienny – do usuwania nieaktywnych kluczy
}

type ruleState struct {
	sig  string
	keys map[string]*keyState
}

// Thresholds to stan reguł progowych silnika w locie.
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

// keep: jak długo trzymać zdarzenia klucza względem najnowszego.
func keep(r *detect.Rule) time.Duration {
	return time.Duration(r.Heimdall.Threshold.Window) + max(time.Duration(r.Heimdall.Suppress), ThresholdLateness)
}

// sync dopasowuje stan do bieżących reguł progowych.
func (t *Thresholds) sync(rules []*detect.Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()
	alive := map[string]bool{}
	for _, r := range rules {
		if !r.IsThreshold() {
			continue
		}
		sig := Signature(r)
		alive[r.ID] = true
		if rs := t.rules[r.ID]; rs == nil || rs.sig != sig {
			t.rules[r.ID] = &ruleState{sig: sig, keys: map[string]*keyState{}}
		}
	}
	for id := range t.rules {
		if !alive[id] {
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
		ks.insert(&entry{Observation: o, emitted: o.InAlert})
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
	ks.entries = insertSorted(ks.entries, e)
	ks.ids[e.EventID] = true
}

// insertSorted wstawia zdarzenie po czasie (przy równym czasie – po id,
// żeby kolejność nie zależała od kolejności napływu).
func insertSorted(es []*entry, e *entry) []*entry {
	i := sort.Search(len(es), func(i int) bool { return entryLess(e, es[i]) })
	es = append(es, nil)
	copy(es[i+1:], es[i:])
	es[i] = e
	return es
}

func entryLess(a, b *entry) bool {
	if !a.EventTime.Equal(b.EventTime) {
		return a.EventTime.Before(b.EventTime)
	}
	return a.EventID < b.EventID
}

// prune usuwa zdarzenia starsze niż najnowsze − keep i najstarsze ponad limit.
func (ks *keyState) prune(keep time.Duration) {
	if len(ks.entries) == 0 {
		return
	}
	cut := ks.entries[len(ks.entries)-1].EventTime.Add(-keep)
	n := sort.Search(len(ks.entries), func(i int) bool { return !ks.entries[i].EventTime.Before(cut) })
	if over := len(ks.entries) - maxEntriesPerKey; over > n {
		n = over
	}
	for _, e := range ks.entries[:n] {
		delete(ks.ids, e.EventID)
	}
	ks.entries = append(ks.entries[:0:0], ks.entries[n:]...)
}

// distinctValue: wartość pola Distinct zdarzenia (puste – „(brak)”).
func distinctValue(r *detect.Rule, ev detect.Event) string {
	f := r.Heimdall.Threshold.Distinct
	if f == "" {
		return ""
	}
	v, _ := ev.Get(f)
	if v = strings.ToLower(v); v == "" || v == "-" {
		return "(brak)"
	}
	return v
}

// observe przyjmuje pasujące zdarzenie reguły progowej. Zwraca obserwację
// do zapisu (nil = zdarzenie już znane) i trafienia – zdarzenia, które
// właśnie zaczęły należeć do alertu.
func (t *Thresholds) observe(r *detect.Rule, ev detect.Event, base alerts.Hit) (*alerts.Observation, []alerts.Hit) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rs := t.rules[r.ID]
	if rs == nil {
		return nil, nil
	}
	if _, ok := rs.keys[base.GroupKey]; !ok && len(rs.keys) >= maxKeysPerRule {
		t.dropped++
		return nil, nil
	}
	ks := rs.key(base.GroupKey, base.GroupFields, t.now())
	if ks.ids[base.EventID] {
		return nil, nil
	}
	o := observation(r, ev, base, rs.sig, t.now())
	ks.insert(&entry{Observation: o})
	ks.prune(keep(r))
	return &o, emit(r, ev, base, ks.entries, nil)
}

func observation(r *detect.Rule, ev detect.Event, base alerts.Hit, sig string, now time.Time) alerts.Observation {
	return alerts.Observation{RuleID: r.ID, Sig: sig, GroupKey: base.GroupKey, GroupFields: base.GroupFields,
		EventID: base.EventID, EventTime: base.EventTime, AgentID: base.AgentID, HostName: base.HostName,
		UserName: base.UserName, SourceIP: base.SourceIP, Value: distinctValue(r, ev), ExpiresAt: now.Add(keep(r))}
}

// emit wyznacza zdarzenia należące do alertów i zwraca trafienia dla tych,
// które jeszcze nie były zgłoszone (emitted). only: jeśli podane, zgłaszane
// są tylko serie zawierające któreś z tych zdarzeń (silnik zapytań – serie
// bez nowych zdarzeń były już zgłoszone wcześniej).
func emit(r *detect.Rule, ev detect.Event, base alerts.Hit, es []*entry, only map[string]bool) []alerts.Hit {
	suppress := time.Duration(r.Heimdall.Suppress)
	marks, wins, found := thresholdMarks(es, r.Heimdall.Threshold, suppress)
	if !found {
		return nil
	}
	var hits []alerts.Hit
	for _, c := range components(es, marks, suppress) {
		if only != nil {
			found := false
			for _, e := range es[c.from:c.to] {
				if only[e.EventID] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		var fresh []*entry
		for _, e := range es[c.from:c.to] {
			if !e.emitted {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		// Opis z pierwszego okna spełniającego próg w tej serii (albo z całej
		// serii, gdy to dalszy ciąg alertu, którego okno już wypadło).
		win := es[c.from:c.to]
		for _, w := range wins {
			if w.from >= c.from && w.to <= c.to {
				win = es[w.from:w.to]
				break
			}
		}
		summary, instr := thresholdTexts(r, ev, win)
		for _, e := range fresh {
			e.emitted = true
			h := base
			h.EventID, h.EventTime, h.AgentID, h.HostName, h.UserName, h.SourceIP =
				e.EventID, e.EventTime, e.AgentID, e.HostName, e.UserName, e.SourceIP
			h.Summary, h.Instructions = summary, instr
			hits = append(hits, h)
		}
	}
	return hits
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
	extra := map[string]string{"count": fmt.Sprint(len(win)), "window": window, "values": ""}
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

// Sweep usuwa klucze bez zdarzeń dłużej niż keep + spóźnienie.
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
		idle := keep(r) + ThresholdLateness
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
