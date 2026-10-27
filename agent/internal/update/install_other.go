// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package update

import "siem/internal/lang"

func startInstaller(string, string) (func() error, error) {
	return nil, lang.Errorf("automatyczna aktualizacja działa tylko w agencie Windows", "automatic updates work only in the Windows agent")
}
