// attackgen buduje słownik MITRE ATT&CK (internal/attack/enterprise.json)
// z oficjalnego pakietu STIX MITRE:
//
//	https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//
// Użycie (przy nowej wersji ATT&CK, zwykle dwa razy w roku):
//
//	go run ./tools/cmd/attackgen <enterprise-attack.json> > internal/attack/enterprise.json
//
// Słownik zawiera tylko to, czego potrzebuje Vardr: taktyki w kolejności
// macierzy, techniki z nazwą, taktykami i platformami, techniki wycofane
// (z następcą, gdy MITRE go wskazało).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

type ref struct {
	Source     string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type object struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Refs       []ref    `json:"external_references"`
	ShortName  string   `json:"x_mitre_shortname"`
	TacticRefs []string `json:"tactic_refs"`
	Version    string   `json:"x_mitre_version"`
	Revoked    bool     `json:"revoked"`
	Deprecated bool     `json:"x_mitre_deprecated"`
	Subtech    bool     `json:"x_mitre_is_subtechnique"`
	Platforms  []string `json:"x_mitre_platforms"`
	RelType    string   `json:"relationship_type"`
	SourceRef  string   `json:"source_ref"`
	TargetRef  string   `json:"target_ref"`
	KillChain  []struct {
		Chain string `json:"kill_chain_name"`
		Phase string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

func (o object) attackID() string {
	for _, r := range o.Refs {
		if r.Source == "mitre-attack" {
			return r.ExternalID
		}
	}
	return ""
}

type Tactic struct {
	ID    string `json:"id"`
	Short string `json:"short"`
	Name  string `json:"name"`
}

type Technique struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics"`
	Platforms  []string `json:"platforms,omitempty"`
	Deprecated bool     `json:"deprecated,omitempty"`
	ReplacedBy string   `json:"replaced_by,omitempty"`
}

type Dict struct {
	Version    string      `json:"version"`
	Source     string      `json:"source"`
	Tactics    []Tactic    `json:"tactics"`
	Techniques []Technique `json:"techniques"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "użycie: attackgen <enterprise-attack.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var bundle struct {
		Objects []object `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	byID := map[string]object{}
	var matrix *object
	d := Dict{Source: "MITRE ATT&CK Enterprise (attack-stix-data)"}
	for i, o := range bundle.Objects {
		byID[o.ID] = o
		switch o.Type {
		case "x-mitre-matrix":
			if matrix == nil || o.Name == "Enterprise ATT&CK" {
				matrix = &bundle.Objects[i]
			}
		case "x-mitre-collection":
			d.Version = o.Version
		}
	}
	if matrix == nil {
		fmt.Fprintln(os.Stderr, "brak macierzy w pakiecie")
		os.Exit(1)
	}
	for _, tr := range matrix.TacticRefs {
		t := byID[tr]
		d.Tactics = append(d.Tactics, Tactic{ID: t.attackID(), Short: t.ShortName, Name: t.Name})
	}
	revokedBy := map[string]string{}
	for _, o := range bundle.Objects {
		if o.Type == "relationship" && o.RelType == "revoked-by" {
			revokedBy[o.SourceRef] = byID[o.TargetRef].attackID()
		}
	}
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" {
			continue
		}
		id := o.attackID()
		if !strings.HasPrefix(id, "T") {
			continue
		}
		t := Technique{ID: id, Name: o.Name, Platforms: o.Platforms, Deprecated: o.Deprecated || o.Revoked,
			ReplacedBy: revokedBy[o.ID]}
		for _, k := range o.KillChain {
			if k.Chain == "mitre-attack" {
				t.Tactics = append(t.Tactics, k.Phase)
			}
		}
		if t.Tactics == nil {
			t.Tactics = []string{}
		}
		d.Techniques = append(d.Techniques, t)
	}
	slices.SortFunc(d.Techniques, func(a, b Technique) int { return strings.Compare(a.ID, b.ID) })
	out, err := json.Marshal(d)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(append(out, '\n'))
	fmt.Fprintf(os.Stderr, "ATT&CK %s: %d taktyk, %d technik\n", d.Version, len(d.Tactics), len(d.Techniques))
}
