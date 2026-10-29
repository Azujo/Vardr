// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package timesync

import (
	"os/exec"
	"runtime"
	"strings"
)

// timeUnits: usługi synchronizacji czasu Linuksa (systemd-timesyncd, chrony
// – Debian/Ubuntu i RHEL/SUSE, ntpd).
var timeUnits = []string{"systemd-timesyncd.service", "chrony.service", "chronyd.service", "ntp.service", "ntpd.service", "ntpsec.service"}

// ServiceState: Linux – „running”, gdy działa któraś usługa czasu,
// „inactive”, gdy żadna; poza Linuksem nieznany.
func ServiceState() string {
	if runtime.GOOS != "linux" {
		return "unknown"
	}
	out, err := exec.Command("systemctl", append([]string{"is-active"}, timeUnits...)...).Output()
	if len(out) == 0 && err != nil {
		return "unknown"
	}
	return activeState(string(out))
}

// activeState: wynik systemctl is-active (wiersz na jednostkę).
func activeState(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "active" {
			return "running"
		}
	}
	return "inactive"
}
