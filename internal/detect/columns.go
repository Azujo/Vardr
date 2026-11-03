// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"fmt"
	"strings"
)

// Częste pola z mapy fields w osobnych kolumnach (M4). Filtr po wartości
// z mapy czyta i rozpakowuje całą mapę: na 2 mln zdarzeń 0,9–1,7 s, po
// kolumnie 40 ms. Kolumny są MATERIALIZED: liczy je ClickHouse z mapy, więc
// writer i agent nic o nich nie wiedzą, a stare części czytają się dalej
// (wartość liczona z mapy przy odczycie). Lista: pola najczęstsze w regułach.
//
// Zmiana listy wymaga nowego skryptu ALTER (deploy/lab/clickhouse/init);
// bit w f_present to pozycja na liście – dopisuj tylko na końcu.
var fieldColumns = []string{
	"CommandLine", "Image", "ParentImage", "TargetFilename", "TargetObject",
	"ScriptBlockText", "Details", "ParentCommandLine", "ProcessName", "TargetUserName",
}

// presentColumn: maska bitowa obecności pól z fieldColumns.
const presentColumn = "f_present"

func columnName(field string) string { return "f_" + strings.ToLower(field) }

func columnIndex(field string) int {
	for i, f := range fieldColumns {
		if f == field {
			return i
		}
	}
	return -1
}

// ColumnDDL zwraca definicje kolumn dla ALTER TABLE ... ADD COLUMN.
func ColumnDDL() []string {
	var out []string
	var present []string
	for i, f := range fieldColumns {
		val, has := mapFieldSQL(f)
		out = append(out, fmt.Sprintf("%s String MATERIALIZED %s CODEC(ZSTD(3))", columnName(f), val))
		present = append(present, fmt.Sprintf("toUInt16(%s) * %d", has, 1<<i))
	}
	return append(out, fmt.Sprintf("%s UInt16 MATERIALIZED %s", presentColumn, strings.Join(present, " + ")))
}

// ExactColumn: kolumna wartości klucza mapy fields, gdy pole nie ma aliasów
// pod innymi nazwami (wyszukiwanie w panelu pyta o dokładnie ten klucz).
func ExactColumn(key string) (string, bool) {
	if columnIndex(key) < 0 {
		return "", false
	}
	if names := aliases[key]; len(names) > 1 {
		return "", false
	}
	return columnName(key), true
}
