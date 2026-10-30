// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package update

import "siem/internal/lang"

// Pakiet: program agenta; dziennik procesu podmieniającego program.
const (
	pkgSuffix = ""
	logPrefix = "update-"
)

// startInstaller: bez Updater.Install (usługa systemd) aktualizacji nie ma.
func startInstaller(string, string) (func() error, error) {
	return nil, lang.Errorf("automatyczna aktualizacja działa tylko w usłudze agenta", "automatic updates work only in the agent service")
}
