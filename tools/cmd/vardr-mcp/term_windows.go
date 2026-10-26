// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// readSecret: wiersz z konsoli bez echa (token nie zostaje na ekranie).
func readSecret(in *bufio.Reader) string {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil && windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT) == nil {
		defer fmt.Println()
		defer windows.SetConsoleMode(h, mode) //nolint:errcheck // przywrócenie trybu konsoli
	}
	return readLine(in)
}
