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

// Engine trzyma bieżący zestaw reguł (podmieniany przy przeładowaniu).
type Engine struct {
	rules atomic.Pointer[[]*detect.Rule]
}

// SetRules podmienia reguły (tylko włączone, z trybem stream albo both).
func (e *Engine) SetRules(all []*detect.Rule) int {
	var active []*detect.Rule
	for _, r := range all {
		if r.Enabled() && (r.Heimdall.Mode == "stream" || r.Heimdall.Mode == "both") {
			active = append(active, r)
		}
	}
	e.rules.Store(&active)
	return len(active)
}

// Evaluate ocenia paczkę zdarzeń i zwraca trafienia.
func (e *Engine) Evaluate(b *model.Batch) []alerts.Hit {
	rp := e.rules.Load()
	if rp == nil {
		return nil
	}
	var hits []alerts.Hit
	for i := range b.Events {
		ev := detect.Event{Event: &b.Events[i]}
		for _, r := range *rp {
			if r.Match(ev) {
				hits = append(hits, hitFor(r, ev))
			}
		}
	}
	return hits
}

func hitFor(r *detect.Rule, ev detect.Event) alerts.Hit {
	h := alerts.Hit{
		RuleID: r.ID, RuleTitle: r.Title, Level: r.Level, Engine: "stream",
		EventID: ev.ID, EventTime: ev.Timestamp, AgentID: ev.AgentID, HostName: ev.HostName,
		UserName: ev.UserName, SourceIP: ev.SourceIP, Summary: summary(r, ev),
	}
	if h.EventTime.IsZero() {
		h.EventTime = ev.Ingested
	}
	if len(r.Heimdall.GroupBy) > 0 {
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
		out = append(out, alerts.RuleInfo{ID: r.ID, Title: r.Title, Level: r.Level, Description: r.Description, Tags: r.Tags,
			File: r.File, Source: r.Source, Mode: r.Heimdall.Mode, Enabled: r.Enabled(), GroupBy: r.Heimdall.GroupBy,
			SuppressS: int(time.Duration(r.Heimdall.Suppress) / time.Second), Instructions: r.Heimdall.Instructions})
	}
	return out
}
