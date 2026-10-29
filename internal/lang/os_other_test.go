// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package lang

import "testing"

func TestLocaleFile(t *testing.T) {
	if got := localeFile("# comment\nLANG=\"pl_PL.UTF-8\"\nLC_TIME=en_GB.UTF-8\n"); got != "pl_PL.UTF-8" {
		t.Fatalf("LANG: %q", got)
	}
	if got := localeFile("LANG=en_US.UTF-8\nLC_MESSAGES=pl_PL.UTF-8\n"); got != "pl_PL.UTF-8" {
		t.Fatalf("LC_MESSAGES: %q", got)
	}
}
