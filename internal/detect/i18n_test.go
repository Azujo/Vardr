// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strings"
	"testing"
)

func TestRuleI18n(t *testing.T) {
	src := `title: Nowe konto
id: test-i18n
level: medium
logsource: {product: windows, service: security}
detection:
  selection: {EventID: 4720}
  condition: selection
vardr:
  instructions: Sprawdź konto {{TargetUserName}}.
  i18n:
    en:
      title: New account
      instructions: |
        Check the account
        {{TargetUserName}}.
`
	r, err := Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	en := r.Vardr.Text("en", r.Title, r.Description)
	if en.Title != "New account" || en.Instructions != "Check the account {{TargetUserName}}." {
		t.Fatalf("tłumaczenie: %+v", en)
	}
	if pl := r.Vardr.Text("de", r.Title, r.Description); pl.Title != "Nowe konto" || pl.Instructions != "" {
		t.Fatalf("brak tłumaczenia – oryginalny tytuł, pusta instrukcja: %+v", pl)
	}
	bad := strings.Replace(src, "    en:", "    xx:", 1)
	if _, err := Parse([]byte(bad), "test.yml"); err == nil || !strings.Contains(err.Error(), "vardr.i18n") {
		t.Fatalf("nieznany język powinien być błędem: %v", err)
	}
}
