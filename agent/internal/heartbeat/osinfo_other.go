// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package heartbeat

import "runtime"

func OSVersion() string { return runtime.GOOS }
