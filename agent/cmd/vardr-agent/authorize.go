// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"siem/agent/internal/config"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/guard"
	"siem/agent/internal/managed"
	"siem/agent/internal/shipper"
	"siem/internal/contract"
	"siem/internal/lang"
)

// authorize: zgoda na zatrzymanie, aktualizację albo usunięcie chronionej
// usługi. Usługa bez ochrony (zwykłe uprawnienia) – bez tokenu. Chroniona:
// token z panelu (agent porównuje skrót; najpierw pobiera świeżą konfigurację
// z panelu, więc token działa od razu po wygenerowaniu). Po przyjęciu tokenu
// polecenie zapisuje znacznik odblokowania i przywraca zwykłe uprawnienia
// usługi; usługa przy zatrzymaniu sprawdza token ponownie i zgłasza
// zatrzymanie tokenem. Zły albo brakujący token trafia do dziennika ochrony
// (alert w panelu).
func authorize(cfgPath, action, token string) error {
	acl, installed, err := serviceProtection()
	if err != nil {
		return err
	}
	if !installed {
		return nil
	}
	if acl == guard.StateOpen && token == "" {
		return nil // usługa bez ochrony
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf(lang.L("konfiguracja agenta (potrzebna do sprawdzenia tokenu): %w", "agent configuration (needed to check the token): %w"), err)
	}
	dir := cfg.StateDir
	user := guard.CurrentUser()
	_, agentID, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, 10*time.Second)
	if err != nil {
		return fmt.Errorf(lang.L("certyfikat agenta: %w", "agent certificate: %w"), err)
	}
	tokens := freshTokens(cfg)
	t, verr := guard.Verify(agentID, token, tokens, guard.Used(dir), time.Now().UTC())
	if verr != nil {
		detail := lang.L("polecenie ", "command ") + action + ": "
		if token == "" {
			detail += lang.L("bez tokenu", "without a token")
		} else {
			detail += verr.Error()
		}
		_, _ = guard.Append(dir, contract.TamperRecord{Kind: contract.TamperBadToken, User: user, Detail: detail})
		if token == "" {
			return guard.ErrNoTokenArg
		}
		// Token z innego agenta (np. starszy wpis o tej samej nazwie komputera):
		// identyfikator wskazuje, przy którym agencie w panelu go wygenerować.
		if errors.Is(verr, guard.ErrNoTokens) || errors.Is(verr, guard.ErrBadToken) {
			return fmt.Errorf(lang.L("%w – identyfikator tego agenta: %s", "%w – this agent's ID: %s"), verr, agentID)
		}
		return verr
	}
	if err := guard.MarkUsed(dir, t.ID); err != nil {
		return err
	}
	if err := guard.WriteUnlock(dir, guard.Unlock{Action: action, Token: token, User: user}); err != nil {
		return err
	}
	_ = guard.RecordState(dir, guard.StateOpen)
	if err := openService(); err != nil {
		guard.RemoveUnlock(dir)
		return fmt.Errorf(lang.L("odblokowanie usługi: %w", "unlocking the service: %w"), err)
	}
	fmt.Printf(lang.L("Token deinstalacji przyjęty (%s) – usługa odblokowana do: %s.\n", "Uninstall token accepted (%s) – service unlocked for: %s.\n"), t.ID, action)
	return nil
}

// freshTokens pobiera konfigurację z panelu (tokeny wygenerowane przed chwilą),
// a bez łączności – ostatnią zapisaną.
func freshTokens(cfg *config.Config) []contract.UninstallToken {
	panelURL := cfg.Server.PanelURL
	if panelURL == "" {
		panelURL, _ = enrollment.PanelURL(cfg.Server.URL)
	}
	if panelURL != "" {
		if client, _, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, 10*time.Second); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			p := &managed.Poller{Client: client, PanelURL: panelURL, StateDir: cfg.StateDir}
			if _, err := p.Fetch(ctx); err != nil {
				fmt.Println(lang.L("uwaga: panel niedostępny – sprawdzam token z ostatniej konfiguracji:", "warning: panel unavailable – checking the token from the last configuration:"), err)
			}
			cancel()
		}
	}
	c, err := managed.Load(cfg.StateDir)
	if err != nil || c == nil {
		return nil
	}
	return c.UninstallTokens
}

// markInstaller: instalator (install, msi-install, upgrade) zmienia usługę
// legalnie – znacznik, żeby agent nie zgłosił zmiany uprawnień ani
// zatrzymania jako sabotażu.
func markInstaller(dir, action string) {
	_ = guard.WriteUnlock(dir, guard.Unlock{Action: action, User: guard.CurrentUser()})
	_ = guard.RecordState(dir, guard.StateOpen)
}
