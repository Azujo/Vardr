// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"strings"
	"testing"
)

// Warunek wyjątku: wartości proste albo krótkie listy, znane modyfikatory,
// bez pustych wartości (pusty warunek ukryłby za dużo).
func TestValidException(t *testing.T) {
	ok := []map[string]any{
		{"Image|endswith": `\backup.exe`, "User": "svc_backup"},
		{"IpAddress|cidr": []any{"10.0.0.0/8", "192.168.0.0/16"}},
		{"EventID": float64(4625)},
	}
	for _, m := range ok {
		if err := validException(m); err != nil {
			t.Errorf("%v: %v", m, err)
		}
	}
	long := make([]any, maxExceptionList+1)
	for i := range long {
		long[i] = "x"
	}
	bad := []map[string]any{
		{},
		{"User": ""},
		{"User": map[string]any{"a": 1}},
		{"User": []any{}},
		{"User": long},
		{"User": strings.Repeat("a", maxExceptionValue+1)},
		{"Image|nieznany": "x"},
		{" ": "x"},
	}
	for _, m := range bad {
		if err := validException(m); err == nil {
			t.Errorf("%v: przyjęty", m)
		}
	}
}
