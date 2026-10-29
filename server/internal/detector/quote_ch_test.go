// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/detect"
)

// Literał z detect.Quote (wartości reguł w SQL) wraca z ClickHouse bez
// zmian – także apostrofy, ukośniki, bajty sterujące, składnia parametrów
// i komentarzy. Wymaga SIEM_TEST_CH_ADDR jak test zgodności.
func TestCompatQuote(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test literałów ClickHouse")
	}
	user := os.Getenv("SIEM_TEST_CH_USER")
	if user == "" {
		user = "default"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr},
		Auth: clickhouse.Auth{Username: user, Password: os.Getenv("SIEM_TEST_CH_PASSWORD")}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var all strings.Builder
	for b := 0; b < 256; b++ {
		all.WriteByte(byte(b))
	}
	cases := []string{"", "'", "''", `\`, `\'`, `\\'`, `'\`, "' OR 1=1 --", "'); DROP DATABASE siem; --",
		"/* x */", "-- x", "?", "? ?", "@p", "{p:String}", "$1", `\x27`, `'`, "\x00'", "a\nb\r\tc",
		"zażółć gęślą jaźń ✓", "\xff\xfe", all.String(), strings.Repeat(`\'`, 1000)}
	for _, s := range cases {
		var got string
		if err := conn.QueryRow(context.Background(), "SELECT "+detect.Quote(s)).Scan(&got); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got != s {
			t.Fatalf("literał zmieniony: %q → %q", s, got)
		}
	}
}
