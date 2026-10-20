package detector

import (
	"sync"
	"sync/atomic"
	"time"

	"siem/internal/alerts"
	"siem/internal/detect"
)

// MaxTrialEntries ogranicza liczbę liczników prób w pamięci między zapisami
// (reguła × godzina × komputer); ponad limit trafienia trafiają do komputera
// „(inne)” – liczba trafień reguły zostaje dokładna.
const MaxTrialEntries = 100_000

// trialOther: komputer zbiorczy ponad limit liczników.
const trialOther = "(inne)"

// Trial liczy trafienia reguł w trybie próbnym (bez alertów): godzinami
// i komputerami, z ostatnim zdarzeniem jako przykładem.
type Trial struct {
	rules atomic.Pointer[[]*detect.Rule]
	mu    sync.Mutex
	acc   map[trialKey]*alerts.TrialHit
}

type trialKey struct {
	rule, host string
	hour       int64
}

func newTrial() *Trial { return &Trial{acc: map[trialKey]*alerts.TrialHit{}} }

// TrialRules wybiera reguły ustawione w panelu jako próbne (bez reguł
// bazowych korelacji – same nie tworzą alertów).
func TrialRules(rules []*detect.Rule, ov map[string]alerts.Override) []*detect.Rule {
	var out []*detect.Rule
	for _, r := range rules {
		if o, ok := ov[r.ID]; ok && o.Trial && !r.CorrelationOnly {
			out = append(out, r)
		}
	}
	return out
}

func (t *Trial) set(rules []*detect.Rule) { t.rules.Store(&rules) }

func (t *Trial) active() []*detect.Rule {
	if p := t.rules.Load(); p != nil {
		return *p
	}
	return nil
}

// observe ocenia zdarzenie regułami próbnymi.
func (t *Trial) observe(ev detect.Event) {
	for _, r := range t.active() {
		if r.Match(ev) {
			t.add(r, ev)
		}
	}
}

func (t *Trial) add(r *detect.Rule, ev detect.Event) {
	at := ev.Timestamp
	if at.IsZero() {
		at = ev.Ingested
	}
	at = at.UTC()
	hour := at.Truncate(time.Hour)
	host := ev.HostName
	t.mu.Lock()
	defer t.mu.Unlock()
	k := trialKey{r.ID, host, hour.Unix()}
	h := t.acc[k]
	if h == nil && len(t.acc) >= MaxTrialEntries {
		k.host = trialOther
		h = t.acc[k]
	}
	if h == nil {
		h = &alerts.TrialHit{RuleID: r.ID, Hour: hour, Host: k.host, First: at, Last: at}
		t.acc[k] = h
	}
	h.Hits++
	if at.Before(h.First) {
		h.First = at
	}
	if !at.Before(h.Last) || h.SampleEventID == "" {
		h.Last = at
		h.SampleEventID = ev.ID
		h.SampleSummary = summary(r, ev)
	}
}

// take zwraca zebrane liczniki i zaczyna od zera.
func (t *Trial) take() []alerts.TrialHit {
	t.mu.Lock()
	acc := t.acc
	t.acc = map[trialKey]*alerts.TrialHit{}
	t.mu.Unlock()
	out := make([]alerts.TrialHit, 0, len(acc))
	for _, h := range acc {
		out = append(out, *h)
	}
	return out
}

// giveBack przywraca liczniki po nieudanym zapisie (dołączy je następny).
func (t *Trial) giveBack(hits []alerts.TrialHit) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, x := range hits {
		k := trialKey{x.RuleID, x.Host, x.Hour.Unix()}
		h := t.acc[k]
		if h == nil {
			if len(t.acc) >= MaxTrialEntries {
				continue // limit pamięci – te trafienia przepadają
			}
			c := x
			t.acc[k] = &c
			continue
		}
		h.Hits += x.Hits
		if x.First.Before(h.First) {
			h.First = x.First
		}
		if x.Last.After(h.Last) {
			h.Last, h.SampleEventID, h.SampleSummary = x.Last, x.SampleEventID, x.SampleSummary
		}
	}
}
