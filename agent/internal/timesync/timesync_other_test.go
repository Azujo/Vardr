// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package timesync

import "testing"

func TestActiveState(t *testing.T) {
	if activeState("inactive\nactive\ninactive\n") != "running" || activeState("inactive\ninactive\n") != "inactive" || activeState("") != "inactive" {
		t.Fatal("activeState")
	}
}
