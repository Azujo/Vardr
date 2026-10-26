// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// readSecret: wiersz z terminala bez echa (token nie zostaje na ekranie).
func readSecret(in *bufio.Reader) string {
	fd := int(os.Stdin.Fd())
	if t, err := unix.IoctlGetTermios(fd, ioctlGetTermios); err == nil {
		quiet := *t
		quiet.Lflag &^= unix.ECHO
		if unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet) == nil {
			defer fmt.Println()
			defer unix.IoctlSetTermios(fd, ioctlSetTermios, t) //nolint:errcheck // przywrócenie terminala
		}
	}
	return readLine(in)
}
