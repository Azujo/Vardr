//go:build !windows

package heartbeat

import "runtime"

func OSVersion() string { return runtime.GOOS }
