// SPDX-License-Identifier: AGPL-3.0-or-later

// Package docs to dokumentacja Vardra wbudowana w siem-api – asystent AI
// i klienci MCP szukają w niej (narzędzie search_docs), np. składni reguł
// czy języka zapytań. Tylko dokumenty dla użytkownika i administratora;
// plany, laboratorium i notatki deweloperskie – pominięte.
package docs

import (
	"embed"
	"math"
	"slices"
	"strings"
	"unicode"
)

//go:embed README.md panel.md reguly.md dekodery.md agent.md operacje.md programy.md instalacja.md architektura.md
//go:embed en/README.md en/panel.md en/rules.md en/decoders.md en/agent.md en/operations.md en/programs.md en/installation.md en/architecture.md
var files embed.FS

// Section to fragment dokumentu od nagłówka ## albo ### do następnego.
type Section struct {
	Doc     string `json:"doc"`  // ścieżka, np. "reguly.md", "en/rules.md"
	Lang    string `json:"lang"` // pl, en
	Heading string `json:"heading"`
	Text    string `json:"text"`
}

var sections = load()

func load() []Section {
	var out []Section
	for _, dir := range []string{".", "en"} {
		ents, _ := files.ReadDir(dir)
		lang := "pl"
		if dir == "en" {
			lang = "en"
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if dir == "en" {
				name = "en/" + name
			}
			raw, err := files.ReadFile(name)
			if err != nil {
				continue
			}
			out = append(out, split(name, lang, string(raw))...)
		}
	}
	return out
}

func split(doc, lang, text string) []Section {
	var out []Section
	title := ""
	cur := Section{Doc: doc, Lang: lang}
	var b strings.Builder
	flush := func() {
		cur.Text = strings.TrimSpace(b.String())
		if cur.Text != "" {
			out = append(out, cur)
		}
		b.Reset()
	}
	inCode := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if !inCode && strings.HasPrefix(line, "# ") && title == "" {
			title = strings.TrimSpace(line[2:])
			cur.Heading = title
			continue
		}
		if !inCode && (strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ")) {
			flush()
			cur = Section{Doc: doc, Lang: lang, Heading: title + " → " + strings.TrimSpace(strings.TrimLeft(line, "# "))}
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	flush()
	return out
}

// terms: słowa zapytania (małe litery, od 3 znaków) skrócone do 6 znaków –
// prosty „rdzeń” dla polskiej odmiany (reguła, reguły, regułę → reguł…).
func terms(q string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '.'
	}) {
		w = strings.Trim(w, ".")
		if r := []rune(w); len(r) >= 3 {
			if len(r) > 6 {
				w = string(r[:6])
			}
			if !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
	}
	return out
}

// Search zwraca do limit najlepiej pasujących fragmentów (język lang
// ma pierwszeństwo przy podobnym wyniku); długie fragmenty są ucinane.
func Search(q, lang string, limit, maxChars int) []Section {
	ts := terms(q)
	if len(ts) == 0 {
		return nil
	}
	lower := make([]string, len(sections))
	df := make([]int, len(ts))
	for i, s := range sections {
		lower[i] = strings.ToLower(s.Heading + "\n" + s.Text)
		for j, t := range ts {
			if strings.Contains(lower[i], t) {
				df[j]++
			}
		}
	}
	type hit struct {
		i     int
		score float64
	}
	var hits []hit
	for i, s := range sections {
		head := strings.ToLower(s.Heading)
		score, matched := 0.0, 0
		for j, t := range ts {
			n := strings.Count(lower[i], t)
			if n == 0 {
				continue
			}
			matched++
			idf := math.Log(1 + float64(len(sections))/float64(df[j]))
			score += idf * (math.Min(float64(n), 8) + 4*float64(strings.Count(head, t)))
		}
		if score == 0 {
			continue
		}
		score *= float64(matched) / float64(len(ts)) // pokrycie zapytania
		if s.Lang == lang {
			score *= 1.3
		}
		hits = append(hits, hit{i, score})
	}
	slices.SortFunc(hits, func(a, b hit) int {
		switch {
		case a.score > b.score:
			return -1
		case a.score < b.score:
			return 1
		}
		return a.i - b.i
	})
	var out []Section
	for _, h := range hits {
		if len(out) == limit {
			break
		}
		s := sections[h.i]
		if r := []rune(s.Text); len(r) > maxChars {
			s.Text = string(r[:maxChars]) + "\n…"
		}
		out = append(out, s)
	}
	return out
}

// Contents: spis dokumentów i nagłówków w języku lang (gdy zapytanie puste).
func Contents(lang string) []string {
	var out []string
	for _, s := range sections {
		if s.Lang == lang {
			out = append(out, s.Doc+": "+s.Heading)
		}
	}
	return out
}
