// SPDX-License-Identifier: AGPL-3.0-or-later

package lang

import "golang.org/x/sys/windows"

// osLanguage: pierwszy preferowany język interfejsu użytkownika (np. pl-PL).
func osLanguage() string {
	if l, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME); err == nil && len(l) > 0 {
		return l[0]
	}
	return envLanguage()
}
