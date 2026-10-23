// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"siem/internal/detect"
)

// importedDir: reguły zaimportowane z SigmaHQ (rules/sigmahq). Testy
// zgodności silników, korpusu i tagów ATT&CK dotyczą reguł utrzymywanych
// w Vardrze – zaimportowane sprawdza osobno TestImportedRules.
const importedDir = "sigmahq/"

func ownRules(rules []*detect.Rule) []*detect.Rule {
	out := rules[:0:0]
	for _, r := range rules {
		if !strings.HasPrefix(r.File, importedDir) {
			out = append(out, r)
		}
	}
	return out
}

func ownSet(set *detect.Set) *detect.Set {
	out := &detect.Set{Rules: ownRules(set.Rules)}
	for _, c := range set.Correlations {
		if !strings.HasPrefix(c.File, importedDir) {
			out.Correlations = append(out.Correlations, c)
		}
	}
	return out
}

// Zaimportowane reguły: wczytują się bez błędów i są domyślnie wyłączone
// (włącza je administrator w panelu po teście na historii).
func TestImportedRules(t *testing.T) {
	if _, err := os.Stat("../../../rules/" + importedDir); err != nil {
		t.Skip("brak rules/sigmahq – nic do sprawdzenia")
	}
	set, errs, err := detect.LoadSet("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range errs {
		if strings.HasPrefix(e.File, importedDir) {
			t.Errorf("%s: %s", e.File, e.Err)
		}
	}
	n := 0
	for _, r := range set.Rules {
		if !strings.HasPrefix(r.File, importedDir) {
			continue
		}
		n++
		if r.Enabled() {
			t.Errorf("%s: zaimportowana reguła włączona w pliku (vardr.enabled: false – włączanie w panelu)", r.File)
		}
	}
	t.Logf("zaimportowanych reguł: %d", n)
}

// Własne reguły mają tłumaczenie na każdy język panelu, a instrukcja
// w tłumaczeniu używa tych samych pól {{…}} co polska.
func TestOwnRulesTranslated(t *testing.T) {
	set, _, err := detect.LoadSet("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	vars := regexp.MustCompile(`\{\{[^}]+\}\}`)
	check := func(file, title, desc string, x detect.Extensions) {
		for _, lang := range detect.Languages {
			tr, ok := x.I18n[lang]
			switch {
			case !ok || tr.Title == "" || tr.Description == "":
				t.Errorf("%s: brak tłumaczenia %s (vardr.i18n.%s: title, description)", file, title, lang)
				continue
			case (x.Instructions == "") != (tr.Instructions == ""):
				t.Errorf("%s: instrukcja tylko w jednym języku (%s)", file, lang)
			}
			want, got := vars.FindAllString(x.Instructions, -1), vars.FindAllString(tr.Instructions, -1)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(slices.Compact(want), slices.Compact(got)) {
				t.Errorf("%s (%s): pola instrukcji %v, w tłumaczeniu %v", file, lang, want, got)
			}
		}
	}
	for _, r := range ownSet(set).Rules {
		check(r.File, r.Title, r.Description, r.Vardr)
	}
	for _, c := range ownSet(set).Correlations {
		check(c.File, c.Title, c.Description, c.Vardr)
	}
}
