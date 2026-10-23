// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"siem/internal/detect"
	"siem/internal/model"
)

// Engine trzyma bieżący zestaw reguł (podmieniany przy przeładowaniu)
// i stan reguł progowych.
type Engine struct {
	rules atomic.Pointer[[]*detect.Rule] // silnik w locie
	all   atomic.Pointer[[]*detect.Rule] // wszystkie wczytane (silnik zapytań)
	th    *Thresholds
	trial *Trial // reguły próbne: trafienia bez alertów
}

// NewEngine tworzy silnik bez reguł.
func NewEngine() *Engine { return &Engine{th: NewThresholds(), trial: newTrial()} }

// SetTrial podmienia reguły próbne (TrialRules).
func (e *Engine) SetTrial(rules []*detect.Rule) { e.trial.set(rules) }

// TakeTrial zwraca trafienia reguł próbnych od ostatniego wywołania.
func (e *Engine) TakeTrial() []alerts.TrialHit { return e.trial.take() }

// GiveBackTrial przywraca trafienia po nieudanym zapisie.
func (e *Engine) GiveBackTrial(hits []alerts.TrialHit) { e.trial.giveBack(hits) }

// SetRules podmienia reguły (tylko włączone, z trybem stream albo both).
func (e *Engine) SetRules(all []*detect.Rule) int {
	var active []*detect.Rule
	for _, r := range all {
		if r.Alerts() && (r.Vardr.Mode == "stream" || r.Vardr.Mode == "both") {
			active = append(active, r)
		}
	}
	e.th.sync(active)
	e.rules.Store(&active)
	e.all.Store(&all)
	return len(active)
}

// IndexRules zwraca reguły silnika zapytań (włączone, index_query albo both).
func (e *Engine) IndexRules() []*detect.Rule {
	if p := e.all.Load(); p != nil {
		return IndexRules(*p)
	}
	return nil
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
		e.trial.observe(ev)
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
		UserName: ev.UserName, SourceIP: ev.SourceIP, Identity: ev.Identity, Summary: summary(r, ev),
		Instructions: detect.Render(r.Vardr.Instructions, ev),
		I18n: texts(func(lang string) alerts.AlertText {
			t := r.Vardr.Text(lang, r.Title, r.Description)
			return alerts.AlertText{Title: t.Title, Summary: summaryIn(lang, ev), Instructions: detect.Render(t.Instructions, ev)}
		}),
	}
	if h.EventTime.IsZero() {
		h.EventTime = ev.Ingested
	}
	if len(r.Vardr.GroupBy) > 0 || r.IsThreshold() {
		h.GroupFields = map[string]string{}
		for _, f := range r.Vardr.GroupBy {
			v, _ := ev.Get(f)
			h.GroupFields[f] = v
		}
		h.GroupKey = strings.Join(r.GroupKey(ev), "\x1f")
		h.Suppress = time.Duration(r.Vardr.Suppress)
	} else {
		h.GroupKey = ev.ID
	}
	return h
}

var summaryFields = []struct{ name, label, en string }{
	{"Threat Name", "zagrożenie", "threat"},
	{"CommandLine", "polecenie", "command"},
	{"ScriptBlockText", "skrypt", "script"},
	{"ImagePath", "program usługi", "service program"},
	{"ServiceName", "usługa", "service"},
	{"MemberName", "członek", "member"},
	{"TargetUserName", "cel", "target"},
	{"QueryName", "zapytanie DNS", "DNS query"},
	{"DestinationIp", "adres docelowy", "destination address"},
}

// summary: krótki opis trafienia (komputer, konto, a przy grupowaniu – pola klucza).
func summary(_ *detect.Rule, ev detect.Event) string { return summaryIn("pl", ev) }

// summaryIn: jak summary, w języku lang.
func summaryIn(lang string, ev detect.Event) string {
	var parts []string
	if ev.HostName != "" {
		parts = append(parts, pick(lang, "komputer ", "computer ")+ev.HostName)
	}
	user := ev.UserName
	if ev.UserDomain != "" && user != "" {
		user = ev.UserDomain + `\` + user
	}
	if user != "" {
		parts = append(parts, pick(lang, "konto ", "account ")+user)
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
		parts = append(parts, pick(lang, f.label, f.en)+": "+v)
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

// ApplyOverrides nadpisuje włączenie reguł ustawieniami z panelu; zwraca
// ustawienia z plików (do pokazania w panelu).
func ApplyOverrides(rules []*detect.Rule, ov map[string]alerts.Override) map[string]bool {
	file := make(map[string]bool, len(rules))
	for _, r := range rules {
		file[r.ID] = r.Enabled()
		if o, ok := ov[r.ID]; ok {
			e := o.Enabled
			r.Vardr.Enabled = &e
		}
	}
	return file
}

// Infos zamienia reguły na opisy dla panelu (fileEnabled – ustawienie
// w pliku; nil = jak obowiązujące).
func Infos(rules []*detect.Rule, fileEnabled map[string]bool) []alerts.RuleInfo {
	out := make([]alerts.RuleInfo, 0, len(rules))
	for _, r := range rules {
		var th *alerts.Threshold
		if t := r.Vardr.Threshold; t != nil {
			th = &alerts.Threshold{Count: t.Count, WindowS: int(time.Duration(t.Window) / time.Second), Distinct: t.Distinct}
		}
		fe, ok := fileEnabled[r.ID]
		if !ok {
			fe = r.Enabled()
		}
		desc := r.Description
		tr := fromRule(r.Vardr.I18n)
		if r.CorrelationOnly {
			desc = "Reguła bazowa korelacji – sama nie tworzy alertów, zasila regułę korelacyjną (generate: false).\n\n" + desc
			tr = ruleTexts(func(lang string) alerts.RuleText {
				t := r.Vardr.Text(lang, r.Title, r.Description)
				t.Description = pick(lang, "", "Base rule of a correlation – it raises no alerts itself, it feeds the correlation rule "+
					"(generate: false).\n\n") + t.Description
				return alerts.RuleText{Title: t.Title, Description: t.Description, Instructions: t.Instructions}
			})
		}
		out = append(out, alerts.RuleInfo{Threshold: th, FileEnabled: fe, ID: r.ID, Title: r.Title, Level: r.Level, Description: desc, Tags: r.Tags,
			File: r.File, Source: r.Source, Mode: r.Vardr.Mode, Enabled: r.Enabled(), GroupBy: r.Vardr.GroupBy,
			SuppressS: int(time.Duration(r.Vardr.Suppress) / time.Second), Instructions: r.Vardr.Instructions, I18n: tr})
	}
	return out
}
