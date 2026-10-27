// SPDX-License-Identifier: AGPL-3.0-or-later

package docs

import (
	"strings"
	"testing"
)

// Wyszukiwanie: polska odmiana trafia w rozdział o regułach, język
// zapytania ma pierwszeństwo, długie fragmenty są ucinane.
func TestSearch(t *testing.T) {
	if len(sections) < 50 {
		t.Fatalf("za mało fragmentów: %d", len(sections))
	}
	got := Search("jak napisać regułę detection selection", "pl", 3, 2000)
	if len(got) == 0 || got[0].Doc != "reguly.md" {
		t.Fatalf("reguły: %+v", got)
	}
	got = Search("correlation rule", "en", 3, 500)
	if len(got) == 0 || got[0].Lang != "en" || !strings.Contains(strings.ToLower(got[0].Heading), "correlation") || len([]rune(got[0].Text)) > 502 {
		t.Fatalf("korelacja: %+v", got)
	}
	if Search("a b", "pl", 3, 100) != nil || len(Contents("en")) == 0 {
		t.Fatal("puste zapytanie / spis")
	}
}
