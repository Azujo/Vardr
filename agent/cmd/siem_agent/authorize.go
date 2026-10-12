//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"siem/agent/internal/config"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/guard"
	"siem/agent/internal/managed"
	"siem/agent/internal/shipper"
	"siem/internal/contract"
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
	acl, err := guard.ServiceACL(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("odczyt uprawnień usługi: %w", err)
	}
	if acl == guard.StateOpen && token == "" {
		return nil // usługa bez ochrony
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("konfiguracja agenta (potrzebna do sprawdzenia tokenu): %w", err)
	}
	dir := cfg.StateDir
	user := guard.CurrentUser()
	_, agentID, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, 10*time.Second)
	if err != nil {
		return fmt.Errorf("certyfikat agenta: %w", err)
	}
	tokens := freshTokens(cfg)
	t, verr := guard.Verify(agentID, token, tokens, guard.Used(dir), time.Now().UTC())
	if verr != nil {
		detail := "polecenie " + action + ": "
		if token == "" {
			detail += "bez tokenu"
		} else {
			detail += verr.Error()
		}
		_, _ = guard.Append(dir, contract.TamperRecord{Kind: contract.TamperBadToken, User: user, Detail: detail})
		if token == "" {
			return guard.ErrNoTokenArg
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
	if err := guard.SetServiceACL(serviceName, guard.StateOpen); err != nil {
		guard.RemoveUnlock(dir)
		return fmt.Errorf("odblokowanie usługi: %w", err)
	}
	fmt.Printf("Token deinstalacji przyjęty (%s) – usługa odblokowana do: %s.\n", t.ID, action)
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
				fmt.Println("uwaga: panel niedostępny – sprawdzam token z ostatniej konfiguracji:", err)
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
