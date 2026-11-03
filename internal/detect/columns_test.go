// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"os"
	"strings"
	"testing"
)

// Skrypt schematu musi mieć dokładnie te wyrażenia, które zastępują odczyt
// z mapy w fieldSQL – inaczej kolumna i Event.Get dawałyby różne wyniki.
func TestColumnsScript(t *testing.T) {
	data, err := os.ReadFile("../../deploy/lab/clickhouse/init/05-fields.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, ddl := range ColumnDDL() {
		if !strings.Contains(script, "ADD COLUMN IF NOT EXISTS "+ddl) {
			t.Errorf("w 05-fields.sh brak:\n%s", ddl)
		}
	}
	if len(fieldColumns) > 16 {
		t.Fatalf("%d pól nie mieści się w %s (UInt16)", len(fieldColumns), presentColumn)
	}
}

func TestFieldColumns(t *testing.T) {
	if v, p := fieldSQL("CommandLine"); v != "f_commandline" || p != "bitTest(f_present, 0)" {
		t.Fatalf("%s %s", v, p)
	}
	if v, _ := fieldSQL("TargetUserName"); v != "f_targetusername" {
		t.Fatal(v)
	}
	// Pole spoza listy i inna wielkość liter – dalej z mapy (jak Event.Get).
	for _, f := range []string{"LogonType", "commandline"} {
		if v, _ := fieldSQL(f); !strings.Contains(v, "fields[") {
			t.Fatalf("%s: %s", f, v)
		}
	}
	// Wyszukiwanie w panelu: tylko pola bez aliasów pod innymi nazwami.
	if c, ok := ExactColumn("CommandLine"); !ok || c != "f_commandline" {
		t.Fatal(c, ok)
	}
	for _, f := range []string{"Image", "TargetObject", "LogonType"} {
		if c, ok := ExactColumn(f); ok {
			t.Fatalf("%s: %s", f, c)
		}
	}
}
