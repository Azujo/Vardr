// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package archiver

import "syscall"

// diskUsage zwraca wolne (dla zwykłego użytkownika) i całkowite miejsce
// systemu plików z katalogiem dir.
func diskUsage(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}
