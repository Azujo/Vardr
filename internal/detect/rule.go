// Package detect to reguły detekcji Gjallarhorna: format Sigma (YAML)
// z rozszerzeniami Heimdalla, kompilacja do drzewa warunków i ocena
// znormalizowanego zdarzenia. Ten sam model reguły posłuży silnikowi
// zapytań (ClickHouse, etap 4d).
//
// Obsługiwany podzbiór Sigmy (MVP, roadmapa sekcja 11):
//   - logsource: product windows; service security|system|application|
//     sysmon|powershell|...; category process_creation|ps_script|
//     network_connection|file_event|dns_query|registry_set
//   - selekcje: mapa pól (AND), lista map (OR), lista słów kluczowych
//   - modyfikatory: contains, startswith, endswith, all, re, cidr, exists
//   - wartości: tekst (bez wielkości liter, * i ? jako maski), liczby, null
//   - warunek: and, or, not, nawiasy, „1 of x*”, „all of x*”, „1 of them”
//
// Wszystko inne (agregacje Sigmy „| count()”, near, base64offset…) jest
// jawnie odrzucane przy wczytaniu reguły – reguła nie działa „trochę”.
package detect

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Poziomy ważności (Sigma level).
var Levels = []string{"informational", "low", "medium", "high", "critical"}

// Rule to reguła po wczytaniu i kompilacji.
type Rule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Level       string   `json:"level"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Author      string   `json:"author,omitempty"`
	References  []string `json:"references,omitempty"`
	False       []string `json:"falsepositives,omitempty"`
	File        string   `json:"file"`
	Source      string   `json:"source"` // treść YAML (do panelu)
	// Name: nazwa Sigmy (odwołania z reguł korelacyjnych).
	Name string `json:"name,omitempty"`

	Heimdall Extensions `json:"heimdall"`
	// CorrelationOnly: reguła bazowa korelacji z generate: false – zasila
	// korelację, sama nie tworzy alertów.
	CorrelationOnly bool `json:"correlation_only,omitempty"`

	match Node
}

// Extensions to rozszerzenia Heimdalla (klucz „heimdall” w YAML).
type Extensions struct {
	// Mode: stream | index_query | both (domyślnie both).
	Mode string `json:"mode" yaml:"mode"`
	// GroupBy: pola klucza alertu – zdarzenia z tymi samymi wartościami
	// w oknie Suppress trafiają do jednego alertu (licznik trafień).
	// Puste = każde zdarzenie to osobny alert.
	GroupBy []string `json:"group_by,omitempty" yaml:"group_by"`
	// Suppress: okno łączenia trafień w jeden alert (domyślnie 1h przy GroupBy).
	Suppress Duration `json:"suppress,omitempty" yaml:"suppress"`
	// Instructions: co ma zrobić analityk (pokazywane w alercie).
	Instructions string `json:"instructions,omitempty" yaml:"instructions"`
	// Enabled: false wyłącza regułę bez usuwania pliku.
	Enabled *bool `json:"enabled,omitempty" yaml:"enabled"`
	// Threshold: reguła progowa – alert dopiero przy Count zdarzeniach
	// (albo Count różnych wartości pola Distinct) z tym samym kluczem
	// GroupBy w dowolnym oknie Window (czas zdarzenia).
	Threshold *Threshold `json:"threshold,omitempty" yaml:"threshold"`
}

// Threshold to próg reguły (count / count distinct w oknie czasowym).
type Threshold struct {
	Count    int      `json:"count" yaml:"count"`
	Window   Duration `json:"window" yaml:"window"`
	Distinct string   `json:"distinct,omitempty" yaml:"distinct"`
}

// Limity progów: okno najwyżej doba, próg 2–10 000.
const (
	MinThresholdWindow = 10 * time.Second
	MaxThresholdWindow = 24 * time.Hour
	MaxThresholdCount  = 10000
)

// Duration to czas w YAML („15m”, „1h”).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("niepoprawny czas %q", n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// Enabled mówi, czy reguła jest włączona.
func (r *Rule) Enabled() bool { return r.Heimdall.Enabled == nil || *r.Heimdall.Enabled }

// Alerts mówi, czy reguła sama tworzy alerty (włączona i nie tylko do korelacji).
func (r *Rule) Alerts() bool { return r.Enabled() && !r.CorrelationOnly }

// Match ocenia zdarzenie.
func (r *Rule) Match(e Event) bool { return r.match.Eval(e) }

// raw to reguła w postaci YAML.
type raw struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Status         string         `yaml:"status"`
	Description    string         `yaml:"description"`
	Author         string         `yaml:"author"`
	References     []string       `yaml:"references"`
	Tags           []string       `yaml:"tags"`
	Level          string         `yaml:"level"`
	FalsePositives []string       `yaml:"falsepositives"`
	Logsource      logsource      `yaml:"logsource"`
	Detection      map[string]any `yaml:"detection"`
	Heimdall       Extensions     `yaml:"heimdall"`
	// Pola Sigmy bez znaczenia dla wykonania – akceptowane, ignorowane.
	Date     string   `yaml:"date"`
	Modified string   `yaml:"modified"`
	Fields   []string `yaml:"fields"`
	License  string   `yaml:"license"`
	Related  any      `yaml:"related"`
	Name     string   `yaml:"name"`
	Taxonomy string   `yaml:"taxonomy"`
}

type logsource struct {
	Product    string `yaml:"product"`
	Service    string `yaml:"service"`
	Category   string `yaml:"category"`
	Definition string `yaml:"definition"`
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

// Parse wczytuje i kompiluje jedną regułę.
func Parse(data []byte, file string) (*Rule, error) {
	var r raw
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("YAML: %w", err)
	}
	switch {
	case r.Title == "":
		return nil, errors.New("brak title")
	case !idRe.MatchString(r.ID):
		return nil, errors.New("id: 3–64 znaki: litery, cyfry, . _ - (np. UUID)")
	case !slices.Contains(Levels, r.Level):
		return nil, fmt.Errorf("level: jedno z %s", strings.Join(Levels, ", "))
	case len(r.Detection) == 0:
		return nil, errors.New("brak detection")
	}
	switch r.Heimdall.Mode {
	case "":
		r.Heimdall.Mode = "both"
	case "stream", "index_query", "both":
	default:
		return nil, errors.New("heimdall.mode: stream, index_query albo both")
	}
	if t := r.Heimdall.Threshold; t != nil {
		switch w := time.Duration(t.Window); {
		case t.Count < 2 || t.Count > MaxThresholdCount:
			return nil, fmt.Errorf("heimdall.threshold.count: od 2 do %d", MaxThresholdCount)
		case w < MinThresholdWindow || w > MaxThresholdWindow:
			return nil, errors.New("heimdall.threshold.window: od 10s do 24h")
		}
		// Łączenie trafień w alert co najmniej na długość okna progu.
		if r.Heimdall.Suppress == 0 {
			r.Heimdall.Suppress = Duration(time.Hour)
		}
		if r.Heimdall.Suppress < t.Window {
			r.Heimdall.Suppress = t.Window
		}
	}
	if len(r.Heimdall.GroupBy) > 0 && r.Heimdall.Suppress == 0 {
		r.Heimdall.Suppress = Duration(time.Hour)
	}
	for _, f := range r.Heimdall.GroupBy {
		if f == "" {
			return nil, errors.New("heimdall.group_by: puste pole")
		}
	}
	ls, err := compileLogsource(r.Logsource)
	if err != nil {
		return nil, fmt.Errorf("logsource: %w", err)
	}
	cond, err := compileDetection(r.Detection)
	if err != nil {
		return nil, fmt.Errorf("detection: %w", err)
	}
	r.Heimdall.Instructions = Unwrap(r.Heimdall.Instructions)
	return &Rule{
		ID: r.ID, Title: r.Title, Description: Unwrap(r.Description), Level: r.Level, Status: r.Status,
		Tags: r.Tags, Author: r.Author, References: r.References, False: r.FalsePositives, File: file,
		Source: string(data), Name: r.Name, Heimdall: r.Heimdall, match: and{ls, cond},
	}, nil
}

// Unwrap łączy linie akapitu (bloki YAML „|” mają twarde końce linii, które
// w panelu i na Discordzie łamałyby zdania); pusta linia oddziela akapity,
// a linie zaczynające się od „-” albo „*” zostają osobno (listy).
func Unwrap(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	var b strings.Builder
	for i, l := range lines {
		l = strings.TrimSpace(l)
		switch {
		case i == 0:
		case l == "" || strings.TrimSpace(lines[i-1]) == "" || strings.HasPrefix(l, "-") || strings.HasPrefix(l, "*"):
			b.WriteString("\n")
		default:
			b.WriteString(" ")
		}
		b.WriteString(l)
	}
	return b.String()
}

// LoadError to błąd jednej reguły (pozostałe działają).
type LoadError struct {
	File string `json:"file"`
	Err  string `json:"error"`
}

// Set to reguły z katalogu: zwykłe (Sigma) i korelacyjne.
type Set struct {
	Rules        []*Rule
	Correlations []*Correlation
}

// LoadDir wczytuje reguły (*.yml, *.yaml) z katalogu i podkatalogów (bez
// korelacji – LoadSet).
func LoadDir(dir string) ([]*Rule, []LoadError, error) {
	set, errs, err := LoadSet(dir)
	if set == nil {
		return nil, errs, err
	}
	return set.Rules, errs, err
}

// Source to treść pliku reguł spoza katalogu (reguły zapisane w panelu).
type Source struct {
	File string // nazwa w panelu i w błędach, np. panel/<id>.yml
	Data []byte
}

// LoadSet wczytuje reguły i korelacje z katalogu i podkatalogów. Plik może
// mieć kilka dokumentów („---”: korelacja z regułami bazowymi). Zwraca
// poprawne reguły i listę błędów; powtórzone id to błąd. Katalog może być
// dowiązaniem (wdrożenie podmienia rules/current atomowo).
func LoadSet(dir string) (*Set, []LoadError, error) { return LoadSetWith(dir, nil) }

// LoadSetWith jak LoadSet, a do tego reguły spoza katalogu (extra – po
// plikach, więc przy powtórzonym id wygrywa plik z repozytorium).
func LoadSetWith(dir string, extra []Source) (*Set, []LoadError, error) {
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	var srcs []Source
	var errs []LoadError
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := strings.ToLower(filepath.Ext(p))
		if d.IsDir() || (ext != ".yml" && ext != ".yaml") {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, LoadError{rel, err.Error()})
			return nil
		}
		srcs = append(srcs, Source{rel, data})
		return nil
	})
	set, lerrs := LoadSources(append(srcs, extra...))
	return set, append(errs, lerrs...), err
}

// LoadSources wczytuje reguły i korelacje z podanych treści (przy
// powtórzonym id wygrywa wcześniejsza).
func LoadSources(srcs []Source) (*Set, []LoadError) {
	set := &Set{}
	var errs []LoadError
	seen := map[string]string{}
	for _, src := range srcs {
		rel := src.File
		docs := splitDocs(src.Data)
		for i, doc := range docs {
			where := rel
			if len(docs) > 1 {
				where = fmt.Sprintf("%s (dokument %d)", rel, i+1)
			}
			var id string
			if IsCorrelation(doc) {
				c, err := ParseCorrelation(doc, rel)
				if err != nil {
					errs = append(errs, LoadError{where, err.Error()})
					continue
				}
				id = c.ID
				if prev, dup := seen[id]; dup {
					errs = append(errs, LoadError{where, fmt.Sprintf("id %s użyte już w %s", id, prev)})
					continue
				}
				set.Correlations = append(set.Correlations, c)
			} else {
				r, err := Parse(doc, rel)
				if err != nil {
					errs = append(errs, LoadError{where, err.Error()})
					continue
				}
				id = r.ID
				if prev, dup := seen[id]; dup {
					errs = append(errs, LoadError{where, fmt.Sprintf("id %s użyte już w %s", id, prev)})
					continue
				}
				set.Rules = append(set.Rules, r)
			}
			seen[id] = where
		}
	}
	sort.Slice(set.Rules, func(i, j int) bool { return set.Rules[i].ID < set.Rules[j].ID })
	sort.Slice(set.Correlations, func(i, j int) bool { return set.Correlations[i].ID < set.Correlations[j].ID })
	// Powiązanie korelacji z regułami bazowymi; generate: false – reguła bazowa
	// zasila tylko korelację (chyba że któraś korelacja ma generate: true).
	generate := map[*Rule]bool{}
	var ok []*Correlation
	for _, c := range set.Correlations {
		if err := c.Resolve(set.Rules); err != nil {
			errs = append(errs, LoadError{c.File, err.Error()})
			continue
		}
		for _, r := range c.Rules {
			generate[r] = generate[r] || c.Generate
		}
		ok = append(ok, c)
	}
	set.Correlations = ok
	for r, g := range generate {
		r.CorrelationOnly = !g
	}
	return set, errs
}

// IsThreshold mówi, czy reguła jest progowa.
func (r *Rule) IsThreshold() bool { return r.Heimdall.Threshold != nil }

// GroupKey zwraca wartości pól klucza alertu (w kolejności GroupBy).
func (r *Rule) GroupKey(e Event) []string {
	out := make([]string, len(r.Heimdall.GroupBy))
	for i, f := range r.Heimdall.GroupBy {
		v, _ := e.Get(f)
		out[i] = strings.ToLower(v)
	}
	return out
}

var placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.]+)\s*\}\}`)

// Render podstawia w tekście (np. instrukcji reguły) zmienne {{Pole}}
// wartościami ze zdarzenia; brak pola – „(brak)”.
func Render(text string, e Event) string { return RenderWith(text, e, nil) }

// RenderWith działa jak Render, ale najpierw sprawdza zmienne dodatkowe
// (np. {{count}} i {{values}} reguły progowej).
func RenderWith(text string, e Event, extra map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		if v, ok := extra[name]; ok {
			return v
		}
		if v, ok := e.Get(name); ok && v != "" && v != "-" {
			return v
		}
		return "(brak)"
	})
}
