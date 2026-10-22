// SPDX-License-Identifier: AGPL-3.0-or-later

package msipatch

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestReplaceAcrossSectors(t *testing.T) {
	old := "VARDR_MSI_SERVER_" + strings.Repeat("=", 111)
	// Mały strumień: napis od pozycji 50 – przez granice minisektorów 0→1→2.
	small := []byte(strings.Repeat("a", 50) + old + strings.Repeat("b", 60))
	// Duży strumień (≥ 4096 B): napis na granicy sektorów 5→7 i drugi raz dalej.
	big := []byte(strings.Repeat("x", 450) + old + strings.Repeat("y", 3000) + old + strings.Repeat("z", 400))
	file := TestFile(small, big)
	out, n, err := Replace(file, old, "192.168.88.98")
	if err != nil || n != 3 {
		t.Fatalf("podmiany: %d %v", n, err)
	}
	c, _ := parse(out)
	ents, _ := c.entries()
	read := func(e entry) string {
		offs, err := c.offsets(e)
		if err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(offs))
		for i, o := range offs {
			b[i] = out[o]
		}
		return string(b)
	}
	want := "192.168.88.98" + strings.Repeat(" ", len(old)-13)
	if s := read(ents[1]); s != strings.Repeat("a", 50)+want+strings.Repeat("b", 60) {
		t.Fatalf("mały strumień: %q", s)
	}
	if s := read(ents[2]); strings.Count(s, want) != 2 || strings.Contains(s, "VARDR") || len(s) != len(big) {
		t.Fatal("duży strumień")
	}
	if len(out) != len(file) || !bytes.Equal(out[:512], file[:512]) {
		t.Fatal("zmieniona struktura pliku")
	}
	if _, _, err := Replace(file, old, strings.Repeat("9", 200)); err == nil {
		t.Fatal("za długa wartość")
	}
	if _, _, err := Replace(file, "NIE_MA_TAKIEGO_NAPISU", "x"); err == nil {
		t.Fatal("brak napisu")
	}
	if _, _, err := Replace([]byte("nie msi"), old, "x"); err == nil {
		t.Fatal("nie CFB")
	}
}

// Prawdziwy instalator agenta (SIEM_TEST_MSI): obie właściwości podmienione.
func TestReplaceRealMSI(t *testing.T) {
	path := os.Getenv("SIEM_TEST_MSI")
	if path == "" {
		t.Skip("brak SIEM_TEST_MSI – pomijam test na prawdziwym MSI")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, n, err := Replace(data, "VARDR_MSI_SERVER_"+strings.Repeat("=", 111), "192.168.88.98")
	if err != nil || n != 1 {
		t.Fatalf("SERVER: %d %v", n, err)
	}
	out, n, err = Replace(out, "VARDR_MSI_TOKEN_"+strings.Repeat("=", 48), "hdt_"+strings.Repeat("A", 43))
	if err != nil || n != 1 {
		t.Fatalf("TOKEN: %d %v", n, err)
	}
	if dst := os.Getenv("SIEM_TEST_MSI_OUT"); dst != "" {
		if err := os.WriteFile(dst, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
