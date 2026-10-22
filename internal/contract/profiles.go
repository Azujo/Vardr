// SPDX-License-Identifier: AGPL-3.0-or-later

package contract

import (
	"fmt"
	"sort"
	"strings"
)

// Channel to kanał Event Log z listą Event ID w konfiguracji.
type Channel struct {
	Name     string
	EventIDs []uint32
}

var (
	securityAll     = []uint32{4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4702, 4719, 1102}
	securityServers = []uint32{4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4728, 4729, 4732, 4733, 4756, 4757}
	securityDC      = []uint32{4768, 4769, 4771, 4776}
	commonChannels  = []Channel{
		{"System", []uint32{7036, 7040, 7045}},
		{"Microsoft-Windows-PowerShell/Operational", []uint32{4104}},
		{"Microsoft-Windows-Sysmon/Operational", []uint32{1, 3, 11, 13, 22}},
		// Microsoft Defender: wykrycia (1006, 1116), działania i ich błędy
		// (1007, 1008, 1117–1119), podejrzane zachowanie (1015), blokady ASR
		// (1121), wyłączenie ochrony i zmiany ustawień (5001, 5004, 5007,
		// 5010, 5012), zablokowana próba zmiany przy ochronie przed
		// naruszeniem (5013).
		{"Microsoft-Windows-Windows Defender/Operational", []uint32{1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 1121,
			5001, 5004, 5007, 5010, 5012, 5013}},
	}
)

// Profiles to profile zbieranych zdarzeń z załącznika B roadmapy.
var Profiles = map[string]string{
	"workstation": "stacja robocza",
	"server":      "serwer (+ zarządzanie kontami i grupami)",
	"dc":          "kontroler domeny (+ Kerberos i NTLM)",
}

// ProfileChannels zwraca kanały dla profilu.
func ProfileChannels(profile string) ([]Channel, error) {
	ids := append([]uint32{}, securityAll...)
	switch profile {
	case "workstation":
	case "server":
		ids = append(ids, securityServers...)
	case "dc":
		ids = append(ids, securityServers...)
		ids = append(ids, securityDC...)
	default:
		names := make([]string, 0, len(Profiles))
		for n := range Profiles {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("nieznany profil %q (dostępne: %s)", profile, strings.Join(names, ", "))
	}
	return append([]Channel{{"Security", ids}}, commonChannels...), nil
}
