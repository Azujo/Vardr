// SPDX-License-Identifier: AGPL-3.0-or-later

package lang

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestOSOverride(t *testing.T) {
	t.Setenv("VARDR_LANG", "en")
	if OS() != "en" {
		t.Fatal("VARDR_LANG=en")
	}
	t.Setenv("VARDR_LANG", "pl")
	if OS() != "pl" {
		t.Fatal("VARDR_LANG=pl")
	}
}

func TestPick(t *testing.T) {
	if Pick("en", "a", "b") != "b" || Pick("pl", "a", "b") != "a" || Pick("de", "a", "b") != "a" {
		t.Fatal("Pick")
	}
}

func TestErrorf(t *testing.T) {
	inner := Errorf("pole %s nieznane", "field %s unknown", "x")
	outer := Errorf("reguła %s: %w", "rule %s: %w", "r1", inner)
	if outer.Error() != "reguła r1: pole x nieznane" || English(outer) != "rule r1: field x unknown" {
		t.Fatalf("%q / %q", outer.Error(), English(outer))
	}
	if !errors.Is(outer, inner) {
		t.Fatal("Unwrap")
	}
	wrapped := fmt.Errorf("plik a.yml: %w", inner)
	if English(wrapped) != "plik a.yml: field x unknown" {
		t.Fatalf("%q", English(wrapped))
	}
	if English(errors.New("zwykły")) != "zwykły" || English(nil) != "" {
		t.Fatal("plain")
	}
}

func TestErrorLogValue(t *testing.T) {
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "err", Errorf("zły", "bad"))
	if !strings.Contains(b.String(), "err=bad") {
		t.Fatal(b.String())
	}
}
