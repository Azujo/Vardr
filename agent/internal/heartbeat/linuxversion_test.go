// SPDX-License-Identifier: AGPL-3.0-or-later

package heartbeat

import "testing"

func TestLinuxVersion(t *testing.T) {
	rel := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n"
	if v := linuxVersion(rel, "6.8.0-45-generic"); v != "Ubuntu 24.04.1 LTS (kernel 6.8.0-45-generic)" {
		t.Fatal(v)
	}
	if v := linuxVersion("", ""); v != "Linux" {
		t.Fatal(v)
	}
}
