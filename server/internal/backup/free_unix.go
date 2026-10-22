// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package backup

import "syscall"

// freeBytes: wolne miejsce w katalogu (dla panelu).
func freeBytes(dir string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
