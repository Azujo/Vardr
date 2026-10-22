// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package timesync

// ServiceState: poza Windows nieznany (agent Linux – później).
func ServiceState() string { return "unknown" }
