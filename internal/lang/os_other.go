// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package lang

import (
	"os"
	"strings"
)

// osLanguage: LC_ALL / LC_MESSAGES / LANG, a bez nich (usługa systemd nie
// dostaje zmiennych sesji) – język systemu z /etc/default/locale (Debian,
// Ubuntu) albo /etc/locale.conf (RHEL, SUSE, Arch).
func osLanguage() string {
	if v := envLanguage(); v != "" {
		return v
	}
	for _, f := range []string{"/etc/default/locale", "/etc/locale.conf"} {
		if data, err := os.ReadFile(f); err == nil {
			if v := localeFile(string(data)); v != "" {
				return v
			}
		}
	}
	return ""
}

// localeFile: LC_ALL, LC_MESSAGES albo LANG z pliku ustawień regionalnych.
func localeFile(text string) string {
	vals := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok {
			vals[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if vals[k] != "" {
			return vals[k]
		}
	}
	return ""
}
