//go:build !windows

package heartbeat

import "runtime"

func osVersion() string { return runtime.GOOS }
