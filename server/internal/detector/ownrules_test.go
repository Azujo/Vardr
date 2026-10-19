package detector

import (
	"os"
	"strings"
	"testing"

	"siem/internal/detect"
)

// importedDir: reguły zaimportowane z SigmaHQ (rules/sigmahq). Testy
// zgodności silników, korpusu i tagów ATT&CK dotyczą reguł utrzymywanych
// w Heimdallu – zaimportowane sprawdza osobno TestImportedRules.
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
			t.Errorf("%s: zaimportowana reguła włączona w pliku (heimdall.enabled: false – włączanie w panelu)", r.File)
		}
	}
	t.Logf("zaimportowanych reguł: %d", n)
}
