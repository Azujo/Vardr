// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows && !linux

package heartbeat

import "runtime"

func OSVersion() string { return runtime.GOOS }
