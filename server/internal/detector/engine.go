// Package detector to silnik detekcji w locie (Gjallarhorn, tryb stream):
// ocena znormalizowanych zdarzeń regułami i przygotowanie trafień do zapisu.
package detector

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"siem/internal/alerts"
	"siem/server/internal/detect"
	"siem/server/internal/model"
)

// Engine trzyma bieżący zestaw reguł (podmieniany przy przeładowaniu)
// i stan reguł progowych.
type Engine struct {
	rules atomic.Pointer[[]*detect.Rule]
	th    *Thresholds
}

// NewEngine tworzy silnik bez reguł.
func NewEngine() *Engine { return &Engine{th: NewThresholds()} }

// SetRules podmienia reguły (tylko włączone, z trybem stream albo both).
func (e *Engine) SetRules(all []*detect.Rule) int {
	var active []*detect.Rule
	for _, r := range all {
		if r.Enabled() && (r.Heimdall.Mode == "stream" || r.Heimdall.Mode == "both") {
			active = append(active, r)
		}
	}
	e.th.sync(active)
	e.rules.Store(&active)
	return len(active)
}

func (e *Engine) active() []*detect.Rule {
	if rp := e.rules.Load(); rp != nil {
		return *rp
	}
	return nil
}

// RestoreThresholds odtwarza stan progów z bazy (start detektora albo
// wycofanie po nieudanym zapisie). Zwraca liczbę wczytanych zdarzeń.
func (e *Engine) RestoreThresholds(obs []alerts.Observation) int {
	return e.th.Restore(e.active(), obs)
}

// SweepThresholds usuwa nieaktywne klucze progów; zwraca liczbę kluczy
// i zdarzeń odrzuconych przez limity pamięci od ostatniego wywołania.
func (e *Engine) SweepThresholds() (keys, dropped int) {
	var th []*detect.Rule
	for _, r := range e.active() {
		if r.IsThreshold() {
			th = append(th, r)
		}
	}
	return e.th.Sweep(th)
}

// Evaluate ocenia paczkę zdarzeń: zwraca trafienia oraz obserwacje reguł
// progowych (do zapisu razem z alertami).
func (e *Engine) Evaluate(b *model.Batch) ([]alerts.Hit, []alerts.Observation) {
	rules := e.active()
	var hits []alerts.Hit
	var obs []alerts.Observation
	for i := range b.Events {
		ev := detect.Event{Event: &b.Events[i]}
		for _, r := range rules {
			if !r.Match(ev) {
				continue
			}
			h := hitFor(r, ev)
			if !r.IsThreshold() {
				hits = append(hits, h)
				continue
			}
			o, th := e.th.observe(r, ev, h)
			if o != nil {
				obs = append(obs, *o)
			}
			hits = append(hits, th...)
		}
	}
	return hits, obs
}

func hitFor(r *detect.Rule, ev detect.Event) alerts.Hit {
	h := alerts.Hit{
		RuleID: r.ID, RuleTitle: r.Title, Level: r.Level, Engine: "stream",
		EventID: ev.ID, EventTime: ev.Timestamp, AgentID: ev.AgentID, HostName: ev.HostName,
		UserName: ev.UserName, SourceIP: ev.SourceIP, Summary: summary(r, ev),
		Instructions: detect.Render(r.Heimdall.Instructions, ev),
	}
	if h.EventTime.IsZero() {
		h.EventTime = ev.Ingested
	}
	if len(r.Heimdall.GroupBy) > 0 || r.IsThreshold() {
		h.GroupFields = map[string]string{}
		for _, f := range r.Heimdall.GroupBy {
			v, _ := ev.Get(f)
			h.GroupFields[f] = v
		}
		h.GroupKey = strings.Join(r.GroupKey(ev), "\x1f")
		h.Suppress = time.Duration(r.Heimdall.Suppress)
	} else {
		h.GroupKey = ev.ID
	}
	return h
}

var summaryFields = []struct{ name, label string }{
	{"CommandLine", "polecenie"},
	{"ScriptBlockText", "skrypt"},
	{"ImagePath", "program usługi"},
	{"ServiceName", "usługa"},
	{"MemberName", "członek"},
	{"TargetUserName", "cel"},
	{"QueryName", "zapytanie DNS"},
	{"DestinationIp", "adres docelowy"},
}

// summary: krótki opis trafienia (komputer, konto, a przy grupowaniu – pola klucza).
func summary(r *detect.Rule, ev detect.Event) string {
	var parts []string
	if ev.HostName != "" {
		parts = append(parts, "komputer "+ev.HostName)
	}
	user := ev.UserName
	if ev.UserDomain != "" && user != "" {
		user = ev.UserDomain + `\` + user
	}
	if user != "" {
		parts = append(parts, "konto "+user)
	}
	// Najważniejsze pola zdarzenia (najwyżej dwa), bez pustych i „-”.
	n := 0
	for _, f := range summaryFields {
		v, ok := ev.Get(f.name)
		if !ok || v == "" || v == "-" || v == ev.UserName {
			continue
		}
		if len([]rune(v)) > 160 {
			v = string([]rune(v)[:159]) + "…"
		}
		parts = append(parts, f.label+": "+v)
		if n++; n == 2 {
			break
		}
	}
	return strings.Join(parts, ", ")
}

// Fingerprint opisuje stan katalogu reguł (zmiana = przeładowanie).
func Fingerprint(dir string) string {
	var b strings.Builder
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s|%d|%d\n", p, fi.Size(), fi.ModTime().UnixNano())
		}
		return nil
	})
	return b.String()
}

// Infos zamienia reguły na opisy dla panelu.
func Infos(rules []*detect.Rule) []alerts.RuleInfo {
	out := make([]alerts.RuleInfo, 0, len(rules))
	for _, r := range rules {
		var th *alerts.Threshold
		if t := r.Heimdall.Threshold; t != nil {
			th = &alerts.Threshold{Count: t.Count, WindowS: int(time.Duration(t.Window) / time.Second), Distinct: t.Distinct}
		}
		out = append(out, alerts.RuleInfo{Threshold: th, ID: r.ID, Title: r.Title, Level: r.Level, Description: r.Description, Tags: r.Tags,
			File: r.File, Source: r.Source, Mode: r.Heimdall.Mode, Enabled: r.Enabled(), GroupBy: r.Heimdall.GroupBy,
			SuppressS: int(time.Duration(r.Heimdall.Suppress) / time.Second), Instructions: r.Heimdall.Instructions})
	}
	return out
}
