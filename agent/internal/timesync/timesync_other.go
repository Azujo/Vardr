//go:build !windows

package timesync

// ServiceState: poza Windows nieznany (agent Linux – później).
func ServiceState() string { return "unknown" }
