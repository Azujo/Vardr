// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sysmon sprawdza, czy na komputerze działa Sysmon (Sysinternals),
// w jakiej wersji i z jaką konfiguracją. Agent niczego nie instaluje –
// tylko zgłasza stan w heartbeacie, a panel porównuje go z wymaganiami grupy.
package sysmon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// State to stan Sysmona.
type State struct {
	Installed  bool   `json:"installed"`
	Service    string `json:"service,omitempty"` // Sysmon64 | Sysmon
	Running    bool   `json:"running"`
	Version    string `json:"version,omitempty"`
	ConfigHash string `json:"config_hash,omitempty"` // SHA-256 (12 znaków) reguł z rejestru sterownika
	Error      string `json:"error,omitempty"`
}

// Check odczytuje stan Sysmona.
func Check() State {
	var st State
	m, err := mgr.Connect()
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer m.Disconnect()
	for _, name := range []string{"Sysmon64", "Sysmon"} {
		s, err := m.OpenService(name)
		if err != nil {
			if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
				st.Error = err.Error()
			}
			continue
		}
		st.Installed, st.Service = true, name
		if q, err := s.Query(); err == nil {
			st.Running = q.State == svc.Running
		}
		if c, err := s.Config(); err == nil {
			st.Version = fileVersion(strings.Trim(strings.Fields(c.BinaryPathName + " ")[0], `"`))
		}
		s.Close()
		break
	}
	if st.Installed {
		st.ConfigHash = configHash()
	}
	return st
}

// configHash: Sysmon trzyma skompilowane reguły w rejestrze sterownika.
func configHash() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	rules, _, err := k.GetBinaryValue("Rules")
	if err != nil || len(rules) == 0 {
		return ""
	}
	sum := sha256.Sum256(rules)
	return hex.EncodeToString(sum[:6])
}

func fileVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return ""
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &n); err != nil || fixed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d", fixed.FileVersionMS>>16, fixed.FileVersionMS&0xffff)
}
