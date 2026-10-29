// SPDX-License-Identifier: AGPL-3.0-or-later

package heartbeat

import "strings"

// linuxVersion składa opis systemu z treści /etc/os-release i wersji jądra.
func linuxVersion(osRelease, kernel string) string {
	name := "Linux"
	for _, line := range strings.Split(osRelease, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME="); ok {
			if v = strings.Trim(v, `"'`); v != "" {
				name = v
			}
			break
		}
	}
	if kernel != "" {
		name += " (kernel " + kernel + ")"
	}
	return name
}
