// SPDX-License-Identifier: AGPL-3.0-or-later

// Package managed to konfiguracja agenta zarządzana z panelu (grupy
// agentów): profil zbieranych zdarzeń i limity zasobów. Lokalny agent.yaml
// decyduje o adresie serwera, certyfikatach i katalogu stanu; panel –
// o kanałach i limitach. Ostatnia konfiguracja z panelu jest zapisywana
// lokalnie, więc agent stosuje ją także wtedy, gdy panel jest niedostępny.
package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"siem/agent/internal/config"
	"siem/agent/internal/setup"
	"siem/internal/contract"
	"siem/internal/lang"
)

const fileName = "managed.json"

// Load wczytuje ostatnią konfigurację z panelu (nil, gdy jej nie ma).
func Load(stateDir string) (*contract.AgentConfig, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, fileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c contract.AgentConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", fileName, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", fileName, err)
	}
	return &c, nil
}

// Save zapisuje konfigurację atomowo.
func Save(stateDir string, c *contract.AgentConfig) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(stateDir, fileName+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, fileName))
}

// Apply zwraca konfigurację efektywną: lokalna z kanałami z profilu grupy
// i limitami nadpisanymi przez panel (pola ustawione w grupie).
func Apply(base *config.Config, m *contract.AgentConfig) (*config.Config, error) {
	eff := *base
	if m == nil {
		return &eff, nil
	}
	// Profil grupy (kanały Event Log) dotyczy agenta Windows; agent Linux
	// zbiera źródła z agent.yaml (journald, auditd), z grupy bierze limity i opcje.
	if len(base.Channels) > 0 || !base.LinuxSources() {
		chans, err := setup.ProfileChannels(m.Profile)
		if err != nil {
			return nil, err
		}
		eff.Channels = make([]config.ChannelConfig, 0, len(chans))
		for _, ch := range chans {
			eff.Channels = append(eff.Channels, config.ChannelConfig{Name: ch.Name, EventIDs: ch.EventIDs})
		}
	}
	l := m.Limits
	if l.Priority != nil {
		eff.Limits.Priority = *l.Priority
	}
	if l.CPUMaxPercent != nil {
		eff.Limits.CPUMaxPercent = *l.CPUMaxPercent
	}
	if l.MemorySoftMB != nil {
		v := *l.MemorySoftMB
		eff.Limits.MemorySoftMB = &v
	}
	if l.MemoryHardMB != nil {
		v := *l.MemoryHardMB
		eff.Limits.MemoryHardMB = &v
	}
	if l.MaxEPS != nil {
		eff.Limits.MaxEPS = *l.MaxEPS
	}
	if l.MaxSendKBps != nil {
		eff.Limits.MaxSendKBps = *l.MaxSendKBps
	}
	if l.BufferMaxMB != nil {
		v := *l.BufferMaxMB
		eff.Buffer.MaxMB = &v
	}
	if l.BufferOnFull != nil {
		eff.Buffer.OnFull = *l.BufferOnFull
	}
	if l.IISLogs != nil {
		eff.IIS.Enabled = *l.IISLogs
	}
	if err := eff.Validate(); err != nil {
		return nil, lang.Errorf("konfiguracja z panelu jest niepoprawna: %w", "the configuration from the panel is invalid: %w", err)
	}
	return &eff, nil
}

// Poller okresowo pobiera konfigurację z panelu.
type Poller struct {
	Client   *http.Client // klient mTLS agenta
	PanelURL string
	StateDir string
	Log      *slog.Logger
	Every    time.Duration // domyślnie 5 min
	// OnChange dostaje nową (zapisaną już) konfigurację.
	OnChange func(*contract.AgentConfig)

	current string // wersja, którą agent ma
}

// Run pobiera konfigurację od razu, a potem co Every.
func (p *Poller) Run(ctx context.Context, current *contract.AgentConfig) {
	if p.Every <= 0 {
		p.Every = 5 * time.Minute
	}
	if current != nil {
		p.current = current.Version
	}
	failing := false
	for {
		changed, err := p.Fetch(ctx)
		switch {
		case err != nil && !failing:
			p.Log.Warn("fetching the configuration from the panel failed – the agent runs on the last known one", "err", err)
			failing = true
		case err == nil:
			if failing {
				p.Log.Info("fetching the configuration from the panel works again")
			}
			failing = false
		}
		if changed != nil && p.OnChange != nil {
			p.OnChange(changed)
		}
		t := time.NewTimer(p.Every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Fetch pobiera konfigurację; zwraca nową, gdy się zmieniła (i zapisuje ją).
func (p *Poller) Fetch(ctx context.Context) (*contract.AgentConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.PanelURL+contract.AgentConfigPath, nil)
	if err != nil {
		return nil, err
	}
	if p.current != "" {
		req.Header.Set("If-None-Match", `"`+p.current+`"`)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, lang.Errorf("panel nie obsługuje konfiguracji agentów (starsza wersja siem-api)", "the panel does not support agent configuration (older siem-api version)")
	default:
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var c contract.AgentConfig
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, lang.Errorf("niepoprawna konfiguracja z panelu: %w", "invalid configuration from the panel: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, lang.Errorf("niepoprawna konfiguracja z panelu: %w", "invalid configuration from the panel: %w", err)
	}
	if c.Version == p.current {
		return nil, nil
	}
	if err := Save(p.StateDir, &c); err != nil {
		return nil, lang.Errorf("zapis konfiguracji: %w", "saving the configuration: %w", err)
	}
	p.current = c.Version
	return &c, nil
}
