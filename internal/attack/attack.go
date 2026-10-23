// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attack to słownik MITRE ATT&CK (Enterprise) i odczyt tagów reguł
// w konwencji Sigmy: attack.t1110.001 (technika), attack.credential_access
// (taktyka), attack.g0016 / attack.s0002 (grupy i oprogramowanie – bez
// mapowania na macierz).
//
// Słownik (enterprise.json) generuje tools/cmd/attackgen z oficjalnego
// pakietu STIX MITRE – aktualizacja przy nowej wersji ATT&CK.
package attack

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

//go:embed enterprise.json
var enterpriseJSON []byte

// Tactic to taktyka (kolumna macierzy).
type Tactic struct {
	ID    string `json:"id"`    // TA0006
	Short string `json:"short"` // credential-access
	Name  string `json:"name"`  // Credential Access
}

// Technique to technika albo podtechnika.
type Technique struct {
	ID         string   `json:"id"` // T1110 albo T1110.001
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics"` // skróty taktyk
	Platforms  []string `json:"platforms,omitempty"`
	Deprecated bool     `json:"deprecated,omitempty"`
	ReplacedBy string   `json:"replaced_by,omitempty"`
}

// Parent zwraca technikę nadrzędną (T1110 dla T1110.001) albo samą siebie.
func (t Technique) Parent() string {
	if i := strings.IndexByte(t.ID, '.'); i > 0 {
		return t.ID[:i]
	}
	return t.ID
}

// URL to strona techniki na attack.mitre.org.
func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.Replace(t.ID, ".", "/", 1) + "/"
}

// Dict to słownik ATT&CK.
type Dict struct {
	Version    string      `json:"version"`
	Source     string      `json:"source"`
	Tactics    []Tactic    `json:"tactics"`
	Techniques []Technique `json:"techniques"`

	byID     map[string]*Technique
	byTactic map[string]*Tactic
}

var (
	once sync.Once
	dict *Dict
)

// Enterprise zwraca wbudowany słownik ATT&CK Enterprise.
func Enterprise() *Dict {
	once.Do(func() {
		d := &Dict{}
		if err := json.Unmarshal(enterpriseJSON, d); err != nil {
			panic("attack: unreadable dictionary: " + err.Error())
		}
		d.index()
		dict = d
	})
	return dict
}

func (d *Dict) index() {
	d.byID = make(map[string]*Technique, len(d.Techniques))
	for i := range d.Techniques {
		d.byID[d.Techniques[i].ID] = &d.Techniques[i]
	}
	d.byTactic = make(map[string]*Tactic, len(d.Tactics))
	for i := range d.Tactics {
		d.byTactic[d.Tactics[i].Short] = &d.Tactics[i]
	}
}

// Technique zwraca technikę po identyfikatorze (T1110.001).
func (d *Dict) Technique(id string) (Technique, bool) {
	t, ok := d.byID[strings.ToUpper(id)]
	if !ok {
		return Technique{}, false
	}
	return *t, true
}

// Tactic zwraca taktykę po skrócie (credential-access).
func (d *Dict) Tactic(short string) (Tactic, bool) {
	t, ok := d.byTactic[short]
	if !ok {
		return Tactic{}, false
	}
	return *t, true
}

// Taktyki z wersji sprzed podziału Defense Evasion (ATT&CK 20) – tag
// rozpoznawany, ale z ostrzeżeniem.
var legacyTactics = map[string][2]string{
	"defense-evasion": {"podzielona w ATT&CK 20 na stealth i defense_impairment", "split in ATT&CK 20 into stealth and defense_impairment"},
}

var (
	techTag  = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)
	otherTag = regexp.MustCompile(`^attack\.[gs]\d{4}$`)
)

// Mapping to techniki i taktyki odczytane z tagów reguły.
type Mapping struct {
	Techniques []Technique `json:"techniques"`
	Tactics    []string    `json:"tactics"` // z tagów (attack.credential_access) i z technik
	Warnings   []string    `json:"warnings,omitempty"`
	// WarningsEn: te same ostrzeżenia po angielsku (panel w innym języku).
	WarningsEn []string `json:"warnings_en,omitempty"`
}

func (m *Mapping) warn(pl, en string) {
	m.Warnings = append(m.Warnings, pl)
	m.WarningsEn = append(m.WarningsEn, en)
}

// Map odczytuje tagi reguły. Taktyki to suma taktyk z tagów i taktyk
// technik (technika bez tagu taktyki i tak trafia do właściwej kolumny).
// Ostrzeżenia: nieznana technika albo taktyka, technika wycofana.
func (d *Dict) Map(tags []string) Mapping {
	m := Mapping{Techniques: []Technique{}, Tactics: []string{}}
	addTactic := func(s string) {
		if !slices.Contains(m.Tactics, s) {
			m.Tactics = append(m.Tactics, s)
		}
	}
	for _, raw := range tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if !strings.HasPrefix(tag, "attack.") {
			continue
		}
		if g := techTag.FindStringSubmatch(tag); g != nil {
			t, ok := d.Technique(g[1])
			if !ok {
				m.warn(fmt.Sprintf("%s: nieznana technika ATT&CK %s", raw, d.Version), fmt.Sprintf("%s: unknown ATT&CK technique %s", raw, d.Version))
				continue
			}
			if t.Deprecated {
				w := fmt.Sprintf("%s: technika %s (%s) wycofana w ATT&CK %s", raw, t.ID, t.Name, d.Version)
				en := fmt.Sprintf("%s: technique %s (%s) deprecated in ATT&CK %s", raw, t.ID, t.Name, d.Version)
				if t.ReplacedBy != "" {
					w += " – zastąpiona przez " + t.ReplacedBy
					en += " – replaced by " + t.ReplacedBy
				}
				m.warn(w, en)
			}
			if !slices.ContainsFunc(m.Techniques, func(x Technique) bool { return x.ID == t.ID }) {
				m.Techniques = append(m.Techniques, t)
			}
			for _, ta := range t.Tactics {
				addTactic(ta)
			}
			continue
		}
		if otherTag.MatchString(tag) {
			continue
		}
		short := strings.ReplaceAll(strings.TrimPrefix(tag, "attack."), "_", "-")
		if _, ok := d.byTactic[short]; ok {
			addTactic(short)
			continue
		}
		if why, ok := legacyTactics[short]; ok {
			m.warn(fmt.Sprintf("%s: taktyka %s", raw, why[0]), fmt.Sprintf("%s: tactic %s", raw, why[1]))
			continue
		}
		m.warn(fmt.Sprintf("%s: nieznany tag ATT&CK", raw), fmt.Sprintf("%s: unknown ATT&CK tag", raw))
	}
	// Kolejność taktyk jak w macierzy.
	slices.SortStableFunc(m.Tactics, func(a, b string) int { return d.tacticIndex(a) - d.tacticIndex(b) })
	return m
}

func (d *Dict) tacticIndex(short string) int {
	for i, t := range d.Tactics {
		if t.Short == short {
			return i
		}
	}
	return len(d.Tactics)
}

// Covers mówi, czy tagi reguły obejmują technikę id (podtechnika pokrywa
// też technikę nadrzędną w zapytaniach „T1110”).
func Covers(m Mapping, id string) bool {
	id = strings.ToUpper(id)
	for _, t := range m.Techniques {
		if t.ID == id || t.Parent() == id {
			return true
		}
	}
	return false
}
