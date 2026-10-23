// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"siem/internal/lang"
)

// Reguły korelacyjne w formacie Sigma Correlation (sigmahq.io, „Sigma
// Correlation Rules”): łączą trafienia reguł bazowych po wspólnych polach
// (group-by) w oknie czasu (timespan).
//
//	event_count       co najmniej N zdarzeń (reguł bazowych) z tym samym kluczem w oknie
//	value_count       co najmniej N różnych wartości pola (condition.field)
//	temporal          każda z reguł bazowych wystąpiła w oknie (dowolna kolejność)
//	temporal_ordered  reguły bazowe wystąpiły w oknie w podanej kolejności
//
// Reguły bazowe wskazuje się po id albo name (mogą być w tym samym pliku,
// rozdzielone „---”). Pola klucza mogą się nazywać inaczej w każdej regule
// bazowej (aliases). generate: false (domyślnie) – reguły bazowe same nie
// tworzą alertów, tylko zasilają korelację.
//
// Nieobsługiwane i odrzucane przy wczytaniu: warunki lt/lte/eq/neq
// (alert przy braku zdarzeń), value_sum/value_avg/value_percentile,
// korelacja korelacji.

// Correlation to reguła korelacyjna po wczytaniu.
type Correlation struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Level       string   `json:"level"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Author      string   `json:"author,omitempty"`
	References  []string `json:"references,omitempty"`
	False       []string `json:"falsepositives,omitempty"`
	File        string   `json:"file"`
	Source      string   `json:"source"`

	Type     string                       `json:"type"`
	RuleRefs []string                     `json:"rules"`
	Rules    []*Rule                      `json:"-"` // reguły bazowe w kolejności RuleRefs
	GroupBy  []string                     `json:"group_by,omitempty"`
	Timespan time.Duration                `json:"timespan"`
	Count    int                          `json:"count,omitempty"`   // event_count, value_count: najmniejsza liczba (gt → +1)
	Field    string                       `json:"field,omitempty"`   // value_count
	Aliases  map[string]map[string]string `json:"aliases,omitempty"` // alias → ref reguły → pole
	Generate bool                         `json:"generate"`
	Vardr    Extensions                   `json:"vardr"`
}

// Typy korelacji.
var CorrelationTypes = []string{"event_count", "value_count", "temporal", "temporal_ordered"}

// Limity okna korelacji (koszt zapytania rośnie z oknem).
const (
	MinCorrelationSpan = time.Minute
	MaxCorrelationSpan = 24 * time.Hour
)

type rawCorrelation struct {
	Title          string   `yaml:"title"`
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Status         string   `yaml:"status"`
	Description    string   `yaml:"description"`
	Author         string   `yaml:"author"`
	References     []string `yaml:"references"`
	Tags           []string `yaml:"tags"`
	Level          string   `yaml:"level"`
	FalsePositives []string `yaml:"falsepositives"`
	Date           string   `yaml:"date"`
	Modified       string   `yaml:"modified"`
	License        string   `yaml:"license"`
	Taxonomy       string   `yaml:"taxonomy"`
	Related        any      `yaml:"related"`
	Correlation    struct {
		Type      string                       `yaml:"type"`
		Rules     []string                     `yaml:"rules"`
		GroupBy   []string                     `yaml:"group-by"`
		Timespan  string                       `yaml:"timespan"`
		Timeframe string                       `yaml:"timeframe"` // starsza nazwa
		Condition map[string]any               `yaml:"condition"`
		Aliases   map[string]map[string]string `yaml:"aliases"`
		Generate  *bool                        `yaml:"generate"`
	} `yaml:"correlation"`
	Vardr  Extensions  `yaml:"vardr"`
	Legacy *Extensions `yaml:"heimdall"` // dawna nazwa klucza
}

// IsCorrelation mówi, czy dokument YAML jest regułą korelacyjną.
func IsCorrelation(data []byte) bool {
	var probe struct {
		Correlation any `yaml:"correlation"`
	}
	return yaml.Unmarshal(data, &probe) == nil && probe.Correlation != nil
}

var timespanRe = regexp.MustCompile(`^(\d+)([smhd])$`)

// ParseTimespan: czas Sigmy („30s”, „15m”, „1h”, „1d”).
func ParseTimespan(s string) (time.Duration, error) {
	m := timespanRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, lang.Errorf("niepoprawny czas %q (np. 15m, 1h, 1d)", "invalid duration %q (e.g. 15m, 1h, 1d)", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

// ParseCorrelation wczytuje regułę korelacyjną (bez powiązania reguł bazowych – Resolve).
func ParseCorrelation(data []byte, file string) (*Correlation, error) {
	var r rawCorrelation
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("YAML: %w", err)
	}
	c := r.Correlation
	if err := useLegacy(&r.Vardr, r.Legacy); err != nil {
		return nil, err
	}
	switch {
	case r.Title == "":
		return nil, lang.Errorf("brak title", "missing title")
	case !idRe.MatchString(r.ID):
		return nil, lang.Errorf("id: 3–64 znaki: litery, cyfry, . _ - (np. UUID)", "id: 3–64 characters: letters, digits, . _ - (e.g. a UUID)")
	case !slices.Contains(Levels, r.Level):
		return nil, lang.Errorf("level: jedno z %s", "level: one of %s", strings.Join(Levels, ", "))
	case !slices.Contains(CorrelationTypes, c.Type):
		return nil, lang.Errorf("correlation.type: jedno z %s", "correlation.type: one of %s", strings.Join(CorrelationTypes, ", "))
	case len(c.Rules) == 0:
		return nil, lang.Errorf("correlation.rules: podaj reguły bazowe (id albo name)", "correlation.rules: list the base rules (id or name)")
	case (c.Type == "temporal" || c.Type == "temporal_ordered") && len(c.Rules) < 2:
		return nil, lang.Errorf("correlation.rules: korelacja czasowa wymaga co najmniej dwóch reguł", "correlation.rules: a temporal correlation needs at least two rules")
	}
	span := c.Timespan
	if span == "" {
		span = c.Timeframe
	}
	ts, err := ParseTimespan(span)
	if err != nil {
		return nil, fmt.Errorf("correlation.timespan: %w", err)
	}
	if ts < MinCorrelationSpan || ts > MaxCorrelationSpan {
		return nil, lang.Errorf("correlation.timespan: od 1m do 24h", "correlation.timespan: from 1m to 24h")
	}
	out := &Correlation{ID: r.ID, Name: r.Name, Title: r.Title, Description: Unwrap(r.Description), Level: r.Level, Status: r.Status,
		Tags: r.Tags, Author: r.Author, References: r.References, False: r.FalsePositives, File: file, Source: string(data),
		Type: c.Type, RuleRefs: c.Rules, GroupBy: c.GroupBy, Timespan: ts, Aliases: c.Aliases, Vardr: r.Vardr}
	if c.Generate != nil {
		out.Generate = *c.Generate
	}
	for _, g := range c.GroupBy {
		if strings.TrimSpace(g) == "" {
			return nil, lang.Errorf("correlation.group-by: puste pole", "correlation.group-by: empty field")
		}
	}
	for alias, m := range c.Aliases {
		if !slices.Contains(c.GroupBy, alias) {
			return nil, lang.Errorf("correlation.aliases: alias %q nie jest w group-by", "correlation.aliases: alias %q is not in group-by", alias)
		}
		for ref := range m {
			if !slices.Contains(c.Rules, ref) {
				return nil, lang.Errorf("correlation.aliases.%s: reguła %q nie jest w rules", "correlation.aliases.%s: rule %q is not in rules", alias, ref)
			}
		}
	}
	switch c.Type {
	case "event_count", "value_count":
		n, err := condCount(c.Condition)
		if err != nil {
			return nil, err
		}
		out.Count = n
		if c.Type == "value_count" {
			f, _ := c.Condition["field"].(string)
			if strings.TrimSpace(f) == "" {
				return nil, lang.Errorf("correlation.condition.field: value_count liczy różne wartości pola – podaj je", "correlation.condition.field: value_count counts distinct values of a field – specify it")
			}
			out.Field = f
		}
	default:
		if len(c.Condition) > 0 {
			return nil, lang.Errorf("correlation.condition: korelacja czasowa nie ma warunku liczbowego", "correlation.condition: a temporal correlation has no numeric condition")
		}
	}
	if h := r.Vardr; h.Mode != "" || len(h.GroupBy) > 0 || h.Threshold != nil {
		return nil, lang.Errorf("vardr: w korelacji tylko instructions, suppress i enabled (klucz i okno są w correlation)", "vardr: a correlation allows only instructions, i18n, suppress and enabled (key and window are in correlation)")
	}
	if out.Vardr.Suppress == 0 {
		out.Vardr.Suppress = Duration(max(time.Hour, ts))
	}
	out.Vardr.Instructions = Unwrap(out.Vardr.Instructions)
	if err := normalizeI18n(&out.Vardr); err != nil {
		return nil, err
	}
	return out, nil
}

// condCount: warunek liczbowy (gte, gt) → najmniejsza liczba spełniająca.
func condCount(cond map[string]any) (int, error) {
	if len(cond) == 0 {
		return 0, lang.Errorf("correlation.condition: podaj warunek, np. gte: 10", "correlation.condition: specify a condition, e.g. gte: 10")
	}
	for k := range cond {
		switch k {
		case "gte", "gt", "field":
		case "lt", "lte", "eq", "neq":
			return 0, lang.Errorf("correlation.condition.%s: nieobsługiwane (alert przy braku zdarzeń) – użyj gte albo gt", "correlation.condition.%s: not supported (alert on missing events) – use gte or gt", k)
		default:
			return 0, lang.Errorf("correlation.condition.%s: nieznany warunek", "correlation.condition.%s: unknown condition", k)
		}
	}
	n, add := 0, 0
	v, ok := cond["gte"]
	if !ok {
		v, ok, add = cond["gt"], true, 1
	}
	switch x := v.(type) {
	case int:
		n = x + add
	default:
		ok = false
	}
	if !ok || n < 2 || n > MaxThresholdCount {
		return 0, lang.Errorf("correlation.condition: liczba od 2 do %d (gte albo gt)", "correlation.condition: a number from 2 to %d (gte or gt)", MaxThresholdCount)
	}
	return n, nil
}

// Resolve wiąże odwołania z regułami bazowymi (po id albo name).
func (c *Correlation) Resolve(rules []*Rule) error {
	c.Rules = c.Rules[:0]
	for _, ref := range c.RuleRefs {
		var found *Rule
		for _, r := range rules {
			if r.ID == ref || (r.Name != "" && r.Name == ref) {
				found = r
				break
			}
		}
		if found == nil {
			return lang.Errorf("correlation.rules: nie ma reguły %q (id albo name; korelacja korelacji nieobsługiwana)", "correlation.rules: no rule %q (id or name; a correlation of correlations is not supported)", ref)
		}
		if found.IsThreshold() {
			return lang.Errorf("correlation.rules: reguła %q jest progowa – korelacja liczy sama, użyj reguły bez progu", "correlation.rules: rule %q has a threshold – the correlation counts by itself, use a rule without a threshold", ref)
		}
		c.Rules = append(c.Rules, found)
	}
	return nil
}

// Enabled mówi, czy korelacja jest włączona.
func (c *Correlation) Enabled() bool { return c.Vardr.Enabled == nil || *c.Vardr.Enabled }

// KeyField zwraca pole klucza (group-by) dla i-tej reguły bazowej (alias albo to samo pole).
func (c *Correlation) KeyField(group string, i int) string {
	if m, ok := c.Aliases[group]; ok {
		if f, ok := m[c.RuleRefs[i]]; ok {
			return f
		}
		if r := c.Rules[i]; r.Name != "" {
			if f, ok := m[r.Name]; ok {
				return f
			}
		}
		if f, ok := m[c.Rules[i].ID]; ok {
			return f
		}
	}
	return group
}

// ---- wczytywanie plików z wieloma dokumentami ----

var docSep = regexp.MustCompile(`(?m)^---[ \t]*\r?$`)

// splitDocs dzieli plik YAML na dokumenty („---”).
func splitDocs(data []byte) [][]byte {
	var out [][]byte
	for _, d := range docSep.Split(string(data), -1) {
		if strings.TrimSpace(stripComments(d)) != "" {
			out = append(out, []byte(strings.TrimLeft(d, "\r\n")))
		}
	}
	return out
}

func stripComments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ---- ocena (wspólna dla silnika i testu w panelu) ----

// CorrEvent to zdarzenie pasujące do reguły bazowej korelacji.
type CorrEvent struct {
	Time  time.Time
	ID    string
	Rules []int  // indeksy reguł bazowych, do których pasuje
	Value string // value_count: wartość pola (małe litery)
	New   bool   // przyjęte w ocenianym przedziale
}

type corrSeries []CorrEvent

func (s corrSeries) Len() int             { return len(s) }
func (s corrSeries) Time(i int) time.Time { return s[i].Time }
func (s corrSeries) Value(i int) string   { return s[i].Value }
func (s corrSeries) Seed(int) bool        { return false }

// Evaluate zwraca grupy zdarzeń jednego klucza, które spełniają korelację
// (każda grupa – jeden alert; tylko grupy z nowym zdarzeniem).
// Zdarzenia muszą być posortowane po czasie.
func (c *Correlation) Evaluate(evs []CorrEvent) [][]CorrEvent {
	if len(evs) == 0 {
		return nil
	}
	var groups [][]CorrEvent
	switch c.Type {
	case "event_count", "value_count":
		th := &Threshold{Count: c.Count, Window: Duration(c.Timespan)}
		if c.Type == "value_count" {
			th.Distinct = c.Field
		}
		s := corrSeries(evs)
		marks, _, found := ThresholdMarks(s, th, time.Duration(c.Vardr.Suppress))
		if !found {
			return nil
		}
		for _, sp := range Components(s, marks, time.Duration(c.Vardr.Suppress)) {
			groups = append(groups, evs[sp.From:sp.To])
		}
	case "temporal":
		groups = c.temporal(evs)
	case "temporal_ordered":
		groups = c.ordered(evs)
	}
	var out [][]CorrEvent
	for _, g := range groups {
		if slices.ContainsFunc(g, func(e CorrEvent) bool { return e.New }) {
			out = append(out, g)
		}
	}
	return out
}

// temporal: okna [t−span, t], w których wystąpiła każda reguła bazowa;
// zachodzące okna łączą się w jedną grupę.
func (c *Correlation) temporal(evs []CorrEvent) [][]CorrEvent {
	n := len(c.Rules)
	marks := make([]bool, len(evs))
	counts := make([]int, n)
	present := 0
	add := func(e CorrEvent, d int) {
		for _, r := range e.Rules {
			if counts[r] == 0 && d > 0 {
				present++
			}
			counts[r] += d
			if counts[r] == 0 && d < 0 {
				present--
			}
		}
	}
	lo := 0
	for hi := range evs {
		add(evs[hi], 1)
		for evs[hi].Time.Sub(evs[lo].Time) > c.Timespan {
			add(evs[lo], -1)
			lo++
		}
		if present == n {
			for k := lo; k <= hi; k++ {
				marks[k] = true
			}
		}
	}
	return markedGroups(evs, marks, c.Timespan)
}

// ordered: łańcuchy r0 < r1 < … < rN-1 w oknie; do alertu – zdarzenia łańcucha.
func (c *Correlation) ordered(evs []CorrEvent) [][]CorrEvent {
	n := len(c.Rules)
	// best[k]: łańcuch do kroku k z najpóźniejszym początkiem (najwięcej czasu na resztę).
	type chain struct {
		start time.Time
		idx   []int
	}
	best := make([]*chain, n)
	marks := make([]bool, len(evs))
	for i, e := range evs {
		// Od końca, żeby jedno zdarzenie pasujące do kilku kroków nie
		// przeszło dwóch kroków naraz.
		for k := n - 1; k >= 0; k-- {
			if !slices.Contains(e.Rules, k) {
				continue
			}
			if k == 0 {
				best[0] = &chain{start: e.Time, idx: []int{i}}
				continue
			}
			p := best[k-1]
			if p == nil || e.Time.Sub(p.start) > c.Timespan || !e.Time.After(evs[p.idx[len(p.idx)-1]].Time) {
				continue
			}
			nc := &chain{start: p.start, idx: append(slices.Clone(p.idx), i)}
			if best[k] == nil || nc.start.After(best[k].start) {
				best[k] = nc
			}
		}
		if last := best[n-1]; last != nil {
			for _, k := range last.idx {
				marks[k] = true
			}
			best[n-1] = nil
		}
	}
	return markedGroups(evs, marks, c.Timespan)
}

// markedGroups: zaznaczone zdarzenia odległe o najwyżej span – jedna grupa.
func markedGroups(evs []CorrEvent, marks []bool, span time.Duration) [][]CorrEvent {
	var out [][]CorrEvent
	var cur []CorrEvent
	for i, e := range evs {
		if !marks[i] {
			continue
		}
		if len(cur) > 0 && e.Time.Sub(cur[len(cur)-1].Time) > span {
			out = append(out, cur)
			cur = nil
		}
		cur = append(cur, e)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// SortCorrEvents sortuje po czasie (stabilnie po id).
func SortCorrEvents(evs []CorrEvent) {
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].Time.Equal(evs[j].Time) {
			return evs[i].Time.Before(evs[j].Time)
		}
		return evs[i].ID < evs[j].ID
	})
}

// CorrelationLateness: jak daleko przed oknem szukać zdarzeń przyjętych
// z opóźnieniem (agent bez łączności, bufor).
const CorrelationLateness = time.Hour

// EventsSQL: zdarzenia reguł bazowych z kluczami, które wystąpiły
// w zdarzeniach przyjętych w (from, to], z okna timespan (+ opóźnienie)
// wstecz. Kolumny: timestamp, fresh (przyjęte w oknie), event_id,
// m (pasujące reguły bazowe), k (klucz), v (wartość value_count).
// Wspólne dla detektora i testu reguły w panelu.
func (c *Correlation) EventsSQL(table string, from, to time.Time, limit int) string {
	conds := make([]string, len(c.Rules))
	for i, r := range c.Rules {
		conds[i] = "(" + r.SQL() + ")"
	}
	// Klucz: pola group-by (z aliasami – inne pole w każdej regule bazowej).
	keyFor := func(i int) string {
		if len(c.GroupBy) == 0 {
			return "tuple('')"
		}
		parts := make([]string, len(c.GroupBy))
		for g, name := range c.GroupBy {
			parts[g] = "lowerUTF8(" + FieldSQL(c.KeyField(name, i)) + ")"
		}
		return "tuple(" + strings.Join(parts, ", ") + ")"
	}
	key := keyFor(0)
	if len(c.Rules) > 1 {
		var cases []string
		for i := range c.Rules {
			cases = append(cases, conds[i], keyFor(i))
		}
		key = "multiIf(" + strings.Join(cases, ", ") + ", " + keyFor(0) + ")"
	}
	val := "''"
	if c.Type == "value_count" {
		val = "lowerUTF8(" + FieldSQL(c.Field) + ")"
	}
	any := strings.Join(conds, " OR ")
	f, t := from.UnixMilli(), to.UnixMilli()
	since := from.Add(-c.Timespan - CorrelationLateness).UnixMilli()
	return fmt.Sprintf(`WITH ks AS (
		SELECT DISTINCT %[1]s AS k FROM %[2]s
		WHERE ingested > fromUnixTimestamp64Milli(%[3]d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%[4]d, 'UTC') AND (%[5]s))
	SELECT timestamp, ingested > fromUnixTimestamp64Milli(%[3]d, 'UTC') AS fresh, event_id, [%[6]s] AS m, %[1]s AS k, %[7]s AS v
	FROM %[2]s
	WHERE ingested > fromUnixTimestamp64Milli(%[8]d, 'UTC') AND ingested <= fromUnixTimestamp64Milli(%[4]d, 'UTC')
		AND (%[5]s) AND k IN (SELECT k FROM ks)
	ORDER BY k, timestamp, event_id
	LIMIT 1 BY event_id
	LIMIT %[9]d`, key, table, f, t, any, strings.Join(conds, ", "), val, since, limit)
}

// ParseText wczytuje reguły i korelacje z tekstu (dokumenty rozdzielone
// „---”) – test w panelu. Reguły bazowe korelacji szukane najpierw w tym
// tekście, potem w known (reguły wdrożone).
func ParseText(data []byte, file string, known []*Rule) (*Set, error) {
	set := &Set{}
	for i, doc := range splitDocs(data) {
		if IsCorrelation(doc) {
			c, err := ParseCorrelation(doc, file)
			if err != nil {
				return nil, lang.Errorf("dokument %d: %w", "document %d: %w", i+1, err)
			}
			set.Correlations = append(set.Correlations, c)
			continue
		}
		r, err := Parse(doc, file)
		if err != nil {
			return nil, lang.Errorf("dokument %d: %w", "document %d: %w", i+1, err)
		}
		set.Rules = append(set.Rules, r)
	}
	for _, c := range set.Correlations {
		if err := c.Resolve(append(slices.Clone(set.Rules), known...)); err != nil {
			return nil, err
		}
	}
	return set, nil
}
