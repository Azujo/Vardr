// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/internal/model"
)

// Reguły korelacyjne Sigma (internal/detect, Correlation) oceniane co
// minutę w ClickHouse razem z korelacjami wbudowanymi: zdarzenia reguł
// bazowych z kluczami, które pojawiły się w nowych zdarzeniach, z okna
// timespan wstecz; ocena (detect.Correlation.Evaluate) w detektorze.
// Alert dotyczy zdarzeń spełniających korelację – para (reguła, zdarzenie)
// jest w alercie najwyżej raz, więc zakładka okien nie dubluje.

// MaxCorrelationRows: najwięcej zdarzeń jednej korelacji w jednym przebiegu
// (ochrona ClickHouse i pamięci detektora; ponad limit – ostrzeżenie).
const MaxCorrelationRows = 50000

// lateness: jak daleko wstecz od okna szukać zdarzeń przyjętych z opóźnieniem.
const lateness = detect.CorrelationLateness

// correlationText: tytuł, opis (z opisem warunku) i instrukcja reguły
// korelacyjnej w języku lang.
func correlationText(c *detect.Correlation, lang string) alerts.RuleText {
	var refs []string
	for _, r := range c.Rules {
		refs = append(refs, r.Vardr.Text(lang, r.Title, r.Description).Title)
	}
	t := c.Vardr.Text(lang, c.Title, c.Description)
	if lang == "pl" {
		t.Instructions = c.Vardr.Instructions
	}
	what := map[string]string{
		"event_count":      fmt.Sprintf(pick(lang, "co najmniej %d zdarzeń reguł bazowych", "at least %d events of the base rules"), c.Count),
		"value_count":      fmt.Sprintf(pick(lang, "co najmniej %d różnych wartości pola %s", "at least %d distinct values of field %s"), c.Count, c.Field),
		"temporal":         pick(lang, "wszystkie reguły bazowe (dowolna kolejność)", "all base rules (any order)"),
		"temporal_ordered": pick(lang, "reguły bazowe w podanej kolejności", "base rules in the given order"),
	}[c.Type]
	desc := t.Description
	if desc != "" {
		desc += "\n\n"
	}
	desc += fmt.Sprintf(pick(lang, "Korelacja %s: %s w oknie %s", "Correlation %s: %s within %s"), c.Type, what, fmtWindow(c.Timespan))
	if len(c.GroupBy) > 0 {
		desc += pick(lang, ", ten sam klucz: ", ", same key: ") + strings.Join(c.GroupBy, ", ")
	}
	desc += pick(lang, ". Reguły bazowe: ", ". Base rules: ") + strings.Join(refs, "; ") + "."
	return alerts.RuleText{Title: t.Title, Description: desc, Instructions: t.Instructions}
}

// CorrelationRuleInfo opisuje regułę korelacyjną dla panelu.
func CorrelationRuleInfo(c *detect.Correlation) alerts.RuleInfo {
	pl := correlationText(c, "pl")
	return alerts.RuleInfo{ID: c.ID, Title: c.Title, Level: c.Level, Description: pl.Description, Tags: c.Tags, File: c.File, Source: c.Source,
		Mode: "correlation", Enabled: c.Enabled(), FileEnabled: c.Enabled(), GroupBy: c.GroupBy,
		SuppressS: int(time.Duration(c.Vardr.Suppress) / time.Second), Instructions: c.Vardr.Instructions,
		I18n: ruleTexts(func(lang string) alerts.RuleText { return correlationText(c, lang) })}
}

// ApplyCorrelationOverrides stosuje ustawienia z panelu (włączenie) do
// reguł korelacyjnych i zwraca ich opisy dla panelu.
func ApplyCorrelationOverrides(cs []*detect.Correlation, ov map[string]alerts.Override) []alerts.RuleInfo {
	out := make([]alerts.RuleInfo, 0, len(cs))
	for _, c := range cs {
		file := c.Enabled()
		if o, ok := ov[c.ID]; ok {
			e := o.Enabled
			c.Vardr.Enabled = &e
		}
		info := CorrelationRuleInfo(c)
		info.FileEnabled = file
		out = append(out, info)
	}
	return out
}

func (c *Correlator) events() string {
	if c.Events == "" {
		return "siem.events"
	}
	return c.Events
}

// RunSigma ocenia reguły korelacyjne Sigma na zdarzeniach przyjętych w (from, to].
// Błąd jednej reguły nie zatrzymuje pozostałych (zwracane razem z trafieniami).
func (c *Correlator) RunSigma(ctx context.Context, rules []*detect.Correlation, from, to time.Time) ([]alerts.Hit, []error) {
	var hits []alerts.Hit
	var errs []error
	for _, cr := range rules {
		if !cr.Enabled() || c.off(cr.ID) {
			continue
		}
		h, err := c.runOne(ctx, cr, from, to)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %w", cr.Title, cr.ID, err))
			continue
		}
		hits = append(hits, h...)
	}
	return hits, errs
}

type keyedEvent struct {
	detect.CorrEvent
	key []string
}

func (c *Correlator) runOne(ctx context.Context, cr *detect.Correlation, from, to time.Time) ([]alerts.Hit, error) {
	rows, err := c.Conn.Query(ctx, cr.EventsSQL(c.events(), from, to, MaxCorrelationRows+1))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string][]detect.CorrEvent{}
	keys := map[string][]string{}
	var order []string
	n := 0
	for rows.Next() {
		var ts time.Time
		var fresh bool
		var id, val string
		var m []uint8
		var k []any
		if err := rows.Scan(&ts, &fresh, &id, &m, &k, &val); err != nil {
			return nil, err
		}
		if n++; n > MaxCorrelationRows {
			return nil, fmt.Errorf("over %d events in the window – narrow the base rules or shorten the timespan", MaxCorrelationRows)
		}
		ev := detect.CorrEvent{Time: ts, ID: id, Value: val, New: fresh}
		for i, ok := range m {
			if ok != 0 {
				ev.Rules = append(ev.Rules, i)
			}
		}
		kv := make([]string, len(k))
		for i, x := range k {
			kv[i] = fmt.Sprint(x)
		}
		ks := strings.Join(kv, "\x1f")
		if _, ok := byKey[ks]; !ok {
			order = append(order, ks)
			keys[ks] = kv
		}
		byKey[ks] = append(byKey[ks], ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type found struct {
		key   []string
		group []detect.CorrEvent
	}
	var all []found
	for _, ks := range order {
		evs := byKey[ks]
		detect.SortCorrEvents(evs)
		for _, g := range cr.Evaluate(evs) {
			all = append(all, found{keys[ks], g})
		}
	}
	if len(all) == 0 {
		return nil, nil
	}
	// Szczegóły zdarzeń z alertów (komputer, konto, pola do instrukcji).
	var ids []string
	for _, f := range all {
		for _, e := range f.group {
			ids = append(ids, e.ID)
		}
	}
	details, err := c.eventDetails(ctx, ids, from.Add(-cr.Timespan-lateness), to)
	if err != nil {
		return nil, err
	}
	var hits []alerts.Hit
	for _, f := range all {
		gf := map[string]string{}
		for i, g := range cr.GroupBy {
			gf[g] = f.key[i]
		}
		last := f.group[len(f.group)-1]
		lastEv := details[last.ID]
		text := func(lang string) alerts.AlertText {
			var used []string
			for _, e := range f.group {
				for _, r := range e.Rules {
					rr := cr.Rules[r]
					if t := rr.Vardr.Text(lang, rr.Title, rr.Description).Title; !slices.Contains(used, t) {
						used = append(used, t)
					}
				}
			}
			keyText := pick(lang, "wszystkie zdarzenia", "all events")
			if len(cr.GroupBy) > 0 {
				var parts []string
				for _, g := range cr.GroupBy {
					parts = append(parts, g+"="+orDash(gf[g]))
				}
				keyText = strings.Join(parts, ", ")
			}
			title := cr.Vardr.Text(lang, cr.Title, cr.Description).Title
			instr := cr.Vardr.Instructions
			if lang != "pl" {
				instr = cr.Vardr.I18n[lang].Instructions
			}
			return alerts.AlertText{Title: title,
				Summary: fmt.Sprintf(pick(lang, "%s: %d zdarzeń w %s (%s) – %s", "%s: %d events in %s (%s) – %s"), keyText, len(f.group),
					fmtSpanIn(lang, f.group[len(f.group)-1].Time.Sub(f.group[0].Time)), strings.Join(used, "; "), title),
				Instructions: detect.RenderWith(instr, detect.Event{Event: &lastEv}, map[string]string{
					"count": fmt.Sprint(len(f.group)), "window": fmtWindow(cr.Timespan), "rules": strings.Join(used, "; "), "key": keyText})}
		}
		pl := text("pl")
		summary, instr, tr := pl.Summary, pl.Instructions, texts(text)
		for _, e := range f.group {
			d := details[e.ID]
			hits = append(hits, alerts.Hit{RuleID: cr.ID, RuleTitle: cr.Title, Level: cr.Level, Engine: "correlation",
				GroupFields: gf, GroupKey: strings.Join(f.key, "\x1f"), Suppress: time.Duration(cr.Vardr.Suppress),
				EventID: e.ID, EventTime: e.Time, AgentID: d.AgentID, HostName: d.HostName, UserName: d.UserName, SourceIP: d.SourceIP,
				Identity: d.Identity, Summary: summary, Instructions: instr, I18n: tr})
		}
	}
	return hits, nil
}

// eventDetails pobiera zdarzenia po id (do opisu alertu i instrukcji).
func (c *Correlator) eventDetails(ctx context.Context, ids []string, since, to time.Time) (map[string]model.Event, error) {
	out := map[string]model.Event{}
	for start := 0; start < len(ids); start += 5000 {
		chunk := ids[start:min(start+5000, len(ids))]
		q := fmt.Sprintf(`SELECT %s FROM %s WHERE ingested > fromUnixTimestamp64Milli(%d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%d, 'UTC')
			AND event_id IN ? LIMIT 1 BY event_id`, eventCols, c.events(),
			since.UnixMilli(), to.UnixMilli())
		rows, err := c.Conn.Query(ctx, q, chunk)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e model.Event
			if err := rows.Scan(detect.EventDest(&e)...); err != nil {
				rows.Close()
				return nil, err
			}
			out[e.ID] = e
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
