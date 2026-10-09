//go:build !windows

package sysmon

// State to stan Sysmona (poza Windows zawsze brak).
type State struct {
	Installed  bool   `json:"installed"`
	Service    string `json:"service,omitempty"`
	Running    bool   `json:"running"`
	Version    string `json:"version,omitempty"`
	ConfigHash string `json:"config_hash,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Check: poza Windows Sysmona nie ma.
func Check() State { return State{} }
