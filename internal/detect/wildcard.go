// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import "strings"

// Maski Sigmy: „*” – dowolny ciąg, „?” – jeden znak, a „\*”, „\?” i „\\” to
// znaki dosłowne. Pojedynczy ukośnik wsteczny (ścieżki Windows) jest zwykłym
// znakiem.

func isEscape(s string, i int) bool {
	return s[i] == '\\' && i+1 < len(s) && (s[i+1] == '*' || s[i+1] == '?' || s[i+1] == '\\')
}

// hasWildcard: czy wartość ma niezescapowaną maskę * albo ?.
func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case isEscape(s, i):
			i++
		case s[i] == '*' || s[i] == '?':
			return true
		}
	}
	return false
}

// unescape usuwa escapowanie Sigmy z wartości bez masek.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isEscape(s, i) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

const (
	anyRun  rune = -1 // *
	anyChar rune = -2 // ?
)

// wildcard dopasowuje maskę do tekstu (oba już małymi literami).
func wildcard(pat, s string) bool {
	var p []rune
	for i := 0; i < len(pat); {
		switch {
		case isEscape(pat, i):
			p = append(p, rune(pat[i+1]))
			i += 2
			continue
		case pat[i] == '*':
			p = append(p, anyRun)
		case pat[i] == '?':
			p = append(p, anyChar)
		default:
			// Znak wielobajtowy UTF-8: dekodujemy cały.
			r := []rune(pat[i:])[0]
			p = append(p, r)
			i += len(string(r))
			continue
		}
		i++
	}
	t := []rune(s)
	// Dopasowanie zachłanne z powrotem do ostatniej gwiazdki.
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && (p[pi] == anyChar || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == anyRun:
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == anyRun {
		pi++
	}
	return pi == len(p)
}
