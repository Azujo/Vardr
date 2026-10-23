// SPDX-License-Identifier: AGPL-3.0-or-later

package guard

import (
	"os"
	"testing"
)

// Teksty dla użytkownika zależą od języka systemu – testy sprawdzają
// polskie (VARDR_LANG ustawione przed pierwszym odczytem języka).
func TestMain(m *testing.M) {
	_ = os.Setenv("VARDR_LANG", "pl")
	os.Exit(m.Run())
}
