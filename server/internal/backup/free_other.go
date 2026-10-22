// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package backup

// freeBytes: poza Linuksem nieznane (usługa działa w kontenerze Linux).
func freeBytes(string) int64 { return 0 }
