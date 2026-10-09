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

	Heimdall Extensions `json:"heimdall"`

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
}

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
	return &Rule{
		ID: r.ID, Title: r.Title, Description: strings.TrimSpace(r.Description), Level: r.Level, Status: r.Status,
		Tags: r.Tags, Author: r.Author, References: r.References, False: r.FalsePositives, File: file,
		Source: string(data), Heimdall: r.Heimdall, match: and{ls, cond},
	}, nil
}

// LoadError to błąd jednej reguły (pozostałe działają).
type LoadError struct {
	File string `json:"file"`
	Err  string `json:"error"`
}

// LoadDir wczytuje reguły (*.yml, *.yaml) z katalogu i podkatalogów.
// Zwraca poprawne reguły i listę błędów; powtórzone id to błąd.
func LoadDir(dir string) ([]*Rule, []LoadError, error) {
	var rules []*Rule
	var errs []LoadError
	seen := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
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
		r, err := Parse(data, rel)
		if err != nil {
			errs = append(errs, LoadError{rel, err.Error()})
			return nil
		}
		if prev, dup := seen[r.ID]; dup {
			errs = append(errs, LoadError{rel, fmt.Sprintf("id %s użyte już w %s", r.ID, prev)})
			return nil
		}
		seen[r.ID] = rel
		rules = append(rules, r)
		return nil
	})
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, errs, err
}

// GroupKey zwraca wartości pól klucza alertu (w kolejności GroupBy).
func (r *Rule) GroupKey(e Event) []string {
	out := make([]string, len(r.Heimdall.GroupBy))
	for i, f := range r.Heimdall.GroupBy {
		v, _ := e.Get(f)
		out[i] = strings.ToLower(v)
	}
	return out
}
