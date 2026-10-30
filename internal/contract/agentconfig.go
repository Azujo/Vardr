// SPDX-License-Identifier: AGPL-3.0-or-later

package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"siem/internal/lang"
)

// AgentConfigPath to endpoint panelu, z którego agent pobiera konfigurację
// (mTLS, certyfikat agenta). Odpowiedź 304, gdy wersja się nie zmieniła.
const AgentConfigPath = "/enroll/v1/config"

// AgentMSIPath to endpoint panelu z bazowym instalatorem MSI agenta (mTLS) –
// automatyczna aktualizacja (AgentConfig.Update).
const AgentMSIPath = "/enroll/v1/agent.msi"

// AgentLinuxPath to endpoint panelu z programem agenta Linux (mTLS) dla
// architektury dopisanej na końcu (amd64, arm64) – AgentConfig.LinuxUpdates.
const AgentLinuxPath = "/enroll/v1/agent-linux/"

// LinuxArchs: architektury agenta Linux budowane w paczce serwera.
var LinuxArchs = []string{"amd64", "arm64"}

// AgentConfig to konfiguracja agenta zarządzana z panelu (grupa agentów).
// Lokalny agent.yaml decyduje o adresie serwera i certyfikatach; panel –
// o zbieranych zdarzeniach (profil) i limitach zasobów.
type AgentConfig struct {
	Version string      `json:"version"` // skrót treści – zmienia się przy każdej zmianie
	GroupID int64       `json:"group_id"`
	Group   string      `json:"group"`
	Profile string      `json:"profile"` // workstation | server | dc
	Limits  AgentLimits `json:"limits"`
	// UninstallTokens: ważne tokeny deinstalacji tego agenta (skróty). Wersja
	// konfiguracji z tokenami ma przyrostek „.<skrót tokenów>” (WithTokens).
	UninstallTokens []UninstallToken `json:"uninstall_tokens,omitempty"`
	// Update: wersja agenta do zainstalowania (grupa z automatycznymi
	// aktualizacjami). Agent starszy niż Version pobiera instalator
	// z AgentMSIPath i sprawdza sumę SHA256. Wersja konfiguracji z
	// aktualizacją ma przyrostek „.<skrót>” (WithUpdate).
	Update *AgentUpdate `json:"update,omitempty"`
	// LinuxUpdates: to samo dla agenta Linux – program dla architektury
	// (klucz: amd64, arm64) z AgentLinuxPath+arch (1.9.0).
	LinuxUpdates map[string]*AgentUpdate `json:"linux_updates,omitempty"`
}

// AgentUpdate to instalator agenta dostępny na serwerze.
type AgentUpdate struct {
	Version string `json:"version"` // np. 0.10.0
	SHA256  string `json:"sha256"`  // instalatora MSI (hex)
	Size    int64  `json:"size"`
}

var (
	agentVersionPattern = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){1,3}$`)
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// MaxAgentMSISize: górna granica instalatora pobieranego przez agenta.
const MaxAgentMSISize = 200 << 20

// Validate sprawdza dane aktualizacji.
func (u AgentUpdate) Validate() error {
	switch {
	case !agentVersionPattern.MatchString(u.Version):
		return lang.Errorf("aktualizacja: niepoprawna wersja %q", "update: invalid version %q", u.Version)
	case !sha256Pattern.MatchString(u.SHA256):
		return lang.Errorf("aktualizacja: niepoprawna suma SHA-256", "update: invalid SHA-256 sum")
	case u.Size <= 0 || u.Size > MaxAgentMSISize:
		return lang.Errorf("aktualizacja: niepoprawny rozmiar instalatora", "update: invalid installer size")
	}
	return nil
}

// NewerVersion: czy wersja a jest nowsza niż b (liczby rozdzielone
// kropkami, brakujące części = 0). Niepoprawna wersja nie jest nowsza
// od niczego – agent nie aktualizuje się na wersję, której nie rozumie.
func NewerVersion(a, b string) bool {
	if !agentVersionPattern.MatchString(a) {
		return false
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 4; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
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
	// Bufor dyskowy agenta (MB, 0 = wyłączony) i zachowanie po zapełnieniu.
	BufferMaxMB  *int    `json:"buffer_max_mb,omitempty"`
	BufferOnFull *string `json:"buffer_on_full,omitempty"` // pause | drop_oldest
	// RequireSysmon: grupa wymaga Sysmona – panel zgłasza komputery bez niego
	// albo z inną konfiguracją niż większość grupy (agent go nie instaluje).
	RequireSysmon *bool `json:"require_sysmon,omitempty"`
	// HeartbeatAlertMin: alert detekcji (Gjallarhorn), gdy agent z tej grupy
	// nie wysłał heartbeatu przez tyle minut (nil/0 = bez alertu – np. stacje
	// wyłączane na noc). Agent go nie używa.
	HeartbeatAlertMin *int `json:"heartbeat_alert_min,omitempty"`
	// HeartbeatNotifyReturn: także powiadomienie, gdy agent wróci (alert
	// utraty łączności zamyka się wtedy sam). Agent go nie używa.
	HeartbeatNotifyReturn *bool `json:"heartbeat_notify_return,omitempty"`
	// Protection: ochrona usługi przed zatrzymaniem i deinstalacją bez tokenu
	// z panelu (nil = włączona). Wyłączenie przywraca zwykłe uprawnienia usługi.
	Protection *bool `json:"protection,omitempty"`
	// AutoUpdate: agenci grupy instalują wersję agenta z serwera sami
	// (nil = wyłączone). Panel dołącza wtedy AgentConfig.Update.
	AutoUpdate *bool `json:"auto_update,omitempty"`
	// IISLogs: agenci grupy czytają logi IIS (pliki W3C; nil = wyłączone,
	// chyba że włączone w agent.yaml).
	IISLogs *bool `json:"iis_logs,omitempty"`
}

// AutoUpdateOn: czy automatyczne aktualizacje są włączone (domyślnie nie).
func (l AgentLimits) AutoUpdateOn() bool { return l.AutoUpdate != nil && *l.AutoUpdate }

// ProtectionOn: czy ochrona agenta jest włączona (domyślnie tak).
func (l AgentLimits) ProtectionOn() bool { return l.Protection == nil || *l.Protection }

// ValidProfiles to profile zdarzeń znane agentowi.
var ValidProfiles = map[string]bool{"workstation": true, "server": true, "dc": true}

// Validate sprawdza zakresy wartości (te same reguły po obu stronach).
func (c AgentConfig) Validate() error {
	if !ValidProfiles[c.Profile] {
		return lang.Errorf("nieznany profil %q", "unknown profile %q", c.Profile)
	}
	if err := validateTokens(c.UninstallTokens); err != nil {
		return err
	}
	if c.Update != nil {
		if err := c.Update.Validate(); err != nil {
			return err
		}
	}
	for arch, u := range c.LinuxUpdates {
		if !slices.Contains(LinuxArchs, arch) || u == nil {
			return lang.Errorf("aktualizacja: nieznana architektura %q", "update: unknown architecture %q", arch)
		}
		if err := u.Validate(); err != nil {
			return err
		}
	}
	return c.Limits.Validate()
}

// Validate sprawdza limity.
func (l AgentLimits) Validate() error {
	var errs []error
	if l.Priority != nil && *l.Priority != "normal" && *l.Priority != "below_normal" && *l.Priority != "background" {
		errs = append(errs, lang.Errorf("priorytet: normal, below_normal albo background", "priority: normal, below_normal or background"))
	}
	if l.CPUMaxPercent != nil && (*l.CPUMaxPercent < 0 || *l.CPUMaxPercent > 100) {
		errs = append(errs, lang.Errorf("limit CPU: 0–100%%", "CPU limit: 0–100%%"))
	}
	for _, m := range []struct {
		pl, en string
		v      *int
	}{{"pamięć miękka", "soft memory", l.MemorySoftMB}, {"pamięć twarda", "hard memory", l.MemoryHardMB}} {
		if v := m.v; v != nil && (*v < 0 || (*v > 0 && *v < 32) || *v > 8192) {
			errs = append(errs, lang.Errorf(m.pl+": 0 (bez limitu) albo 32–8192 MB", m.en+": 0 (no limit) or 32–8192 MB"))
		}
	}
	if l.MemorySoftMB != nil && l.MemoryHardMB != nil && *l.MemoryHardMB > 0 && *l.MemorySoftMB > *l.MemoryHardMB {
		errs = append(errs, lang.Errorf("pamięć miękka nie może być większa niż twarda", "the soft memory limit cannot be greater than the hard one"))
	}
	if l.MaxEPS != nil && (*l.MaxEPS < 0 || *l.MaxEPS > 1_000_000) {
		errs = append(errs, lang.Errorf("limit zdarzeń/s: 0–1 000 000", "events/s limit: 0–1,000,000"))
	}
	if l.MaxSendKBps != nil && (*l.MaxSendKBps < 0 || *l.MaxSendKBps > 10_000_000) {
		errs = append(errs, lang.Errorf("limit łącza: 0–10 000 000 KiB/s", "bandwidth limit: 0–10,000,000 KiB/s"))
	}
	if l.BufferMaxMB != nil && (*l.BufferMaxMB < 0 || *l.BufferMaxMB > 102400) {
		errs = append(errs, lang.Errorf("bufor dyskowy: 0 (wyłączony) – 102 400 MB", "disk buffer: 0 (disabled) – 102,400 MB"))
	}
	if l.HeartbeatAlertMin != nil && (*l.HeartbeatAlertMin < 0 || (*l.HeartbeatAlertMin > 0 && *l.HeartbeatAlertMin < 5) ||
		*l.HeartbeatAlertMin > 10080) {
		errs = append(errs, lang.Errorf("alarm po utracie łączności: 0 (wyłączony) albo 5–10 080 min", "alert after losing contact: 0 (disabled) or 5–10,080 min"))
	}
	if l.BufferOnFull != nil && *l.BufferOnFull != "pause" && *l.BufferOnFull != "drop_oldest" {
		errs = append(errs, lang.Errorf("pełny bufor: pause albo drop_oldest", "full buffer: pause or drop_oldest"))
	}
	return lang.Join(errs...)
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

// WithTokens dołącza tokeny deinstalacji agenta; wersja dostaje przyrostek
// z ich skrótu, więc agent pobiera konfigurację po wygenerowaniu tokenu.
func (c AgentConfig) WithTokens(ts []UninstallToken) AgentConfig {
	c.UninstallTokens = ts
	c.Version = BaseVersion(c.Version)
	if len(ts) > 0 {
		data, _ := json.Marshal(ts)
		sum := sha256.Sum256(data)
		c.Version += "." + hex.EncodeToString(sum[:4])
	}
	return c
}

// WithUpdate dołącza aktualizację agenta; wersja dostaje przyrostek
// z jej skrótu, więc agent pobiera konfigurację po zmianie instalatora.
// Wywoływane po WithTokens (ta zaczyna od wersji bazowej).
func (c AgentConfig) WithUpdate(u *AgentUpdate) AgentConfig {
	c.Update = u
	if u != nil {
		sum := sha256.Sum256([]byte(u.Version + "/" + u.SHA256))
		c.Version += ".u" + hex.EncodeToString(sum[:4])
	}
	return c
}

// WithLinuxUpdates dołącza programy agenta Linux; wersja dostaje przyrostek
// z ich skrótu (po WithUpdate).
func (c AgentConfig) WithLinuxUpdates(us map[string]*AgentUpdate) AgentConfig {
	c.LinuxUpdates = nil
	if len(us) > 0 {
		c.LinuxUpdates = us
		data, _ := json.Marshal(us) // klucze mapy w kolejności – skrót stały
		sum := sha256.Sum256(data)
		c.Version += ".l" + hex.EncodeToString(sum[:4])
	}
	return c
}

// BaseVersion to wersja konfiguracji grupy (bez przyrostka tokenów agenta).
func BaseVersion(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}
