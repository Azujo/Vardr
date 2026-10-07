package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// AgentConfigPath to endpoint panelu, z którego agent pobiera konfigurację
// (mTLS, certyfikat agenta). Odpowiedź 304, gdy wersja się nie zmieniła.
const AgentConfigPath = "/enroll/v1/config"

// AgentConfig to konfiguracja agenta zarządzana z panelu (grupa agentów).
// Lokalny agent.yaml decyduje o adresie serwera i certyfikatach; panel –
// o zbieranych zdarzeniach (profil) i limitach zasobów.
type AgentConfig struct {
	Version string      `json:"version"` // skrót treści – zmienia się przy każdej zmianie
	GroupID int64       `json:"group_id"`
	Group   string      `json:"group"`
	Profile string      `json:"profile"` // workstation | server | dc
	Limits  AgentLimits `json:"limits"`
}

// AgentLimits to limity zasobów agenta („kaganiec”). Wskaźnik nil = wartość
// z lokalnego agent.yaml (lub domyślna agenta).
type AgentLimits struct {
	Priority      *string  `json:"priority,omitempty"`        // normal | below_normal | background
	CPUMaxPercent *float64 `json:"cpu_max_percent,omitempty"` // % całego komputera, 0 = brak
	MemorySoftMB  *int     `json:"memory_soft_mb,omitempty"`
	MemoryHardMB  *int     `json:"memory_hard_mb,omitempty"`
	MaxEPS        *int     `json:"max_eps,omitempty"`
	MaxSendKBps   *int     `json:"max_send_kbps,omitempty"`
}

// ValidProfiles to profile zdarzeń znane agentowi.
var ValidProfiles = map[string]bool{"workstation": true, "server": true, "dc": true}

// Validate sprawdza zakresy wartości (te same reguły po obu stronach).
func (c AgentConfig) Validate() error {
	if !ValidProfiles[c.Profile] {
		return fmt.Errorf("nieznany profil %q", c.Profile)
	}
	return c.Limits.Validate()
}

// Validate sprawdza limity.
func (l AgentLimits) Validate() error {
	var errs []error
	if l.Priority != nil && *l.Priority != "normal" && *l.Priority != "below_normal" && *l.Priority != "background" {
		errs = append(errs, errors.New("priorytet: normal, below_normal albo background"))
	}
	if l.CPUMaxPercent != nil && (*l.CPUMaxPercent < 0 || *l.CPUMaxPercent > 100) {
		errs = append(errs, errors.New("limit CPU: 0–100%"))
	}
	for name, v := range map[string]*int{"pamięć miękka": l.MemorySoftMB, "pamięć twarda": l.MemoryHardMB} {
		if v != nil && (*v < 0 || (*v > 0 && *v < 32) || *v > 8192) {
			errs = append(errs, fmt.Errorf("%s: 0 (bez limitu) albo 32–8192 MB", name))
		}
	}
	if l.MemorySoftMB != nil && l.MemoryHardMB != nil && *l.MemoryHardMB > 0 && *l.MemorySoftMB > *l.MemoryHardMB {
		errs = append(errs, errors.New("pamięć miękka nie może być większa niż twarda"))
	}
	if l.MaxEPS != nil && (*l.MaxEPS < 0 || *l.MaxEPS > 1_000_000) {
		errs = append(errs, errors.New("limit zdarzeń/s: 0–1 000 000"))
	}
	if l.MaxSendKBps != nil && (*l.MaxSendKBps < 0 || *l.MaxSendKBps > 10_000_000) {
		errs = append(errs, errors.New("limit łącza: 0–10 000 000 KiB/s"))
	}
	return errors.Join(errs...)
}

// ComputeVersion wyznacza wersję z treści (profil i limity).
func (c AgentConfig) ComputeVersion() string {
	data, _ := json.Marshal(struct {
		Profile string      `json:"p"`
		Limits  AgentLimits `json:"l"`
	}{c.Profile, c.Limits})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
