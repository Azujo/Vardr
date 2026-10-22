// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	p, err := Parse(`user:jkowalski code:4625 HOST:PC0* -action:logged-out "invoke expression" powershell fields.TargetUserName:admin ip:10.0.5.23`)
	if err != nil {
		t.Fatal(err)
	}
	var sqls []string
	var args []any
	for _, c := range p.Conds {
		sqls = append(sqls, c.SQL)
		args = append(args, c.Args...)
	}
	wantSQL := []string{
		"user_name = ?",
		"event_code = ?",
		"startsWith(host_name, ?)",
		"NOT (event_action = ?)",
		"fields[?] = ?",
		"source_ip = toIPv6OrDefault(?)",
	}
	if !reflect.DeepEqual(sqls, wantSQL) {
		t.Fatalf("SQL:\n%v\nchcę\n%v", sqls, wantSQL)
	}
	wantArgs := []any{"jkowalski", uint32(4625), "pc0", "logged-out", "TargetUserName", "admin", "10.0.5.23"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("argumenty: %v", args)
	}
	if !reflect.DeepEqual(p.Text, []string{"invoke expression", "powershell"}) {
		t.Fatalf("tekst: %v", p.Text)
	}
	tc, ok := p.TextCondition()
	if !ok || strings.Count(tc.SQL, "?") != 4 || len(tc.Args) != 4 {
		t.Fatalf("warunek tekstu: %+v", tc)
	}
}

func TestParseIgnoresUnknownFieldsAsText(t *testing.T) {
	// "C:\Windows" czy "http://x" to tekst, nie pole.
	p, err := Parse(`C:\Windows\System32 http://example.com`)
	if err != nil || len(p.Conds) != 0 || len(p.Text) != 2 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, q := range []string{
		`code:abc`,
		`"bez końca`,
		`fields.a'b:1`,
		`ip:10.0.*`,
		strings.Repeat("x ", 25),
	} {
		if _, err := Parse(q); err == nil {
			t.Errorf("%q: oczekiwano błędu", q)
		}
	}
}

// Wartości nigdy nie trafiają do treści SQL – tylko do parametrów.
func TestValuesNeverInSQL(t *testing.T) {
	p, err := Parse(`user:x'OR'1'='1 "'; DROP TABLE siem.events --" host:a)--`)
	if err != nil {
		t.Fatal(err)
	}
	conds := p.Conds
	if tc, ok := p.TextCondition(); ok {
		conds = append(conds, tc)
	}
	for _, c := range conds {
		if strings.ContainsAny(c.SQL, "'") || strings.Contains(c.SQL, "DROP") || strings.Contains(c.SQL, "OR'1") {
			t.Fatalf("wartość w SQL: %s", c.SQL)
		}
	}
}
