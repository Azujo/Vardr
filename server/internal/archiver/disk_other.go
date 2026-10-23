// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package archiver

import "errors"

// diskUsage: archiwizator działa na Linuksie; na innych systemach (testy)
// miejsce nie jest sprawdzane.
func diskUsage(string) (free, total uint64, err error) {
	return 0, 0, errors.New("disk space measurement not supported")
}
