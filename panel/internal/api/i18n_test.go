// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Panel tłumaczy błędy API po kodzie (web/src/locales/<język>/errors.json),
// a polski opis z serwera jest zapasowy. Każdy kod zwracany przez serwer musi
// mieć tłumaczenie angielskie – inaczej użytkownik zobaczy opis po polsku.
func TestErrorCodesTranslated(t *testing.T) {
	raw, err := os.ReadFile("../../web/src/locales/en/errors.json")
	if err != nil {
		t.Fatal(err)
	}
	var en map[string]string
	if err := json.Unmarshal(raw, &en); err != nil {
		t.Fatalf("errors.json: %v", err)
	}
	re := regexp.MustCompile(`writeError\(\s*w,\s*[^,]+,\s*"([a-z0-9_]+)"\s*,`)
	missing := map[string]string{}
	found := 0
	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllSubmatch(src, -1) {
			found++
			if _, ok := en[string(m[1])]; !ok {
				missing[string(m[1])] = path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 100 {
		t.Fatalf("znaleziono tylko %d wywołań writeError – wzorzec nie pasuje do kodu?", found)
	}
	for code, path := range missing {
		t.Errorf("kod błędu %q (%s) bez tłumaczenia w locales/en/errors.json", code, path)
	}
}
