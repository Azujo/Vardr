// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package heartbeat

import (
	"os"
	"strings"
)

// OSVersion: dystrybucja z /etc/os-release i wersja jądra, np.
// „Ubuntu 24.04.1 LTS (kernel 6.8.0-45-generic)”.
func OSVersion() string {
	data, _ := os.ReadFile("/etc/os-release")
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return linuxVersion(string(data), strings.TrimSpace(string(kernel)))
}
