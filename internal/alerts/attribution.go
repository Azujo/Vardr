// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"strings"

	"gopkg.in/yaml.v3"

	"siem/internal/lang"
)

// SigmaHQDir: katalog reguł zaimportowanych z SigmaHQ (rules/sigmahq,
// docs/reguly.md – „Import reguł SigmaHQ”).
const SigmaHQDir = "sigmahq/"

// Attribution to wskazanie autora i źródła reguły zaimportowanej z SigmaHQ.
// Licencja Detection Rule License 1.1 wymaga zachowania autora także
// w komunikatach z trafień (alerty, powiadomienia).
type Attribution struct {
	Author     string `json:"author"`
	Source     string `json:"source"`
	RuleURL    string `json:"rule_url"`
	License    string `json:"license"`
	LicenseURL string `json:"license_url"`
}

// SigmaHQAttribution zwraca autora i źródło reguły z SigmaHQ (nil dla
// reguł Vardra i wbudowanych). Autor z treści reguły (pole author).
func (r RuleInfo) SigmaHQAttribution() *Attribution {
	if !strings.HasPrefix(r.File, SigmaHQDir) {
		return nil
	}
	var meta struct {
		Author string `yaml:"author"`
	}
	_ = yaml.Unmarshal([]byte(r.Source), &meta)
	// Pusty autor – reguła bez pola author (panel i powiadomienie piszą
	// „autor nieznany” w swoim języku).
	return &Attribution{
		Author:     strings.TrimSpace(meta.Author),
		Source:     "SigmaHQ",
		RuleURL:    "https://github.com/SigmaHQ/sigma/blob/master/rules/" + strings.TrimPrefix(r.File, SigmaHQDir),
		License:    "Detection Rule License (DRL) 1.1",
		LicenseURL: "https://github.com/SigmaHQ/Detection-Rule-License",
	}
}

// Line opisuje autora i źródło jednym zdaniem (powiadomienia, język l).
func (a *Attribution) Line(l string) string {
	author := a.Author
	if author == "" {
		author = lang.Pick(l, "autor nieznany (brak pola author)", "unknown author (no author field)")
	}
	return author + lang.Pick(l, " – reguła ", " – rule from ") + a.Source + " (" + a.License + "): " + a.RuleURL
}
