// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package guard

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// BootTime to chwila startu systemu (btime z /proc/stat).
func BootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	return parseBootTime(string(data))
}

func parseBootTime(stat string) time.Time {
	for _, l := range strings.Split(stat, "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(n, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// CurrentUser to konto, z którego działa polecenie; przez sudo – konto
// użytkownika, który je wywołał („jan (sudo)”).
func CurrentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u + " (sudo)"
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(os.Geteuid())
}
