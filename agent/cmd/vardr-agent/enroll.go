// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/setup"
	"siem/internal/lang"
)

type enrollOptions struct {
	server, token, ca, panel, dir, profile string
}

// enrollOnly rejestruje agenta tokenem i przygotowuje samodzielny katalog
// (certyfikaty + agent.yaml) bez instalowania usługi – do testów, do
// uruchomienia w konsoli (vardr-agent run) albo do własnych skryptów.
// Nie wymaga uprawnień administratora.
func enrollOnly(o enrollOptions) error {
	if o.server == "" || o.token == "" || o.dir == "" {
		return errors.New(lang.L("użycie: vardr-agent enroll -server <adres> -token <token> -dir <katalog> [-ca ca.crt] [-panel URL] [-profile …]", "usage: vardr-agent enroll -server <address> -token <token> -dir <directory> [-ca ca.crt] [-panel URL] [-profile …]"))
	}
	serverURL, err := setup.ServerURL(o.server)
	if err != nil {
		return err
	}
	if o.panel == "" {
		if o.panel, err = enrollment.PanelURL(serverURL); err != nil {
			return err
		}
	}
	if o.ca == "" {
		exe, _ := os.Executable()
		o.ca = filepath.Join(filepath.Dir(exe), "ca.crt")
	}
	caPEM, err := os.ReadFile(o.ca)
	if err != nil {
		return fmt.Errorf(lang.L("plik CA (-ca): %w", "CA file (-ca): %w"), err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New(lang.L("niepoprawny plik CA", "invalid CA file"))
	}
	if _, err := os.Stat(filepath.Join(o.dir, "certs", "agent.key")); err == nil {
		return fmt.Errorf(lang.L("%s zawiera już klucz agenta – wskaż pusty katalog", "%s already contains an agent key – choose an empty directory"), o.dir)
	}

	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, keyPEM, err := enrollment.Register(ctx, o.panel, roots, o.token, enrollment.Info{Hostname: host, OS: heartbeat.OSVersion(), Version: version})
	if err != nil {
		return err
	}
	certDir := filepath.Join(o.dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), caPEM, 0o644); err != nil {
		return err
	}
	if err := enrollment.WritePair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), []byte(res.Certificate), keyPEM); err != nil {
		return err
	}
	profile := o.profile
	if profile == "" {
		profile = res.Profile
	}
	cfg, err := setup.GenerateConfig(setup.Options{ServerURL: serverURL, Profile: profile})
	if err != nil {
		return err
	}
	cfg += "\n# Katalog stanu obok konfiguracji (rejestracja poleceniem vardr-agent enroll).\nstate_dir: state\n"
	cfgPath := filepath.Join(o.dir, "agent.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	fmt.Printf(lang.L("Zarejestrowano agenta %s (profil %s, certyfikat ważny do %s).\n", "Agent %s enrolled (profile %s, certificate valid until %s).\n"), res.AgentID, profile, res.NotAfter.Local().Format("2006-01-02"))
	fmt.Printf("Konfiguracja: %s\nUruchomienie w konsoli: vardr-agent -config %s run\n", cfgPath, cfgPath)
	return nil
}

// upgrade podmienia program zainstalowanej usługi na wersję, z której
// uruchomiono polecenie. Konfiguracja, certyfikaty i stan zostają.
func upgrade(cfgPath, token string) error {
	if err := requireAdmin("Aktualizacja agenta"); err != nil {
		return err
	}
	if _, err := queryService(); err != nil {
		return errors.New(lang.L("agent nie jest zainstalowany – użyj vardr-agent install", "the agent is not installed – use vardr-agent install"))
	}
	if err := authorize(cfgPath, "upgrade", token); err != nil {
		return err
	}
	if token == "" {
		markInstaller(dataDir, "upgrade") // usługa bez ochrony
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if samePath(src, installExe) {
		return fmt.Errorf(lang.L("uruchom upgrade z folderu NOWEJ wersji programu, nie z %s", "run upgrade from the folder of the NEW program version, not from %s"), installDir)
	}
	fmt.Printf("Aktualizacja agenta do wersji %s\n", version)
	if err := withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State != svc.Stopped {
			if _, err := s.Control(svc.Stop); err != nil {
				return protectedErr(err)
			}
			return waitState(s, svc.Stopped, 30*time.Second)
		}
		return nil
	}); err != nil {
		return fmt.Errorf(lang.L("zatrzymanie usługi: %w", "stopping the service: %w"), err)
	}
	fmt.Println(lang.L("  [1/3] Usługa zatrzymana", "  [1/3] Service stopped"))

	// Kopia poprzedniej wersji – powrót: zatrzymać usługę i przywrócić plik .previous.
	// Wersje 0.7.x mają program pod dawną nazwą (legacyExe).
	prev := installExe
	if !fileExists(prev) {
		prev = legacyExe
	}
	_ = os.Remove(installExe + ".previous")
	if err := copyFile(prev, installExe+".previous"); err != nil {
		return fmt.Errorf("kopia poprzedniej wersji: %w", err)
	}
	var copyErr error
	for i := 0; i < 10; i++ { // Windows zwalnia plik programu chwilę po zatrzymaniu procesu
		if copyErr = copyFile(src, installExe); copyErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if copyErr != nil {
		_ = startService()
		return fmt.Errorf(lang.L("podmiana programu: %w (uruchomiono poprzednią wersję)", "replacing the program: %w (the previous version was started)"), copyErr)
	}
	if err := moveServiceBinary(cfgPath); err != nil {
		_ = startService()
		return err
	}
	fmt.Printf(lang.L("  [2/3] Program:       %s (poprzednia wersja: %s.previous)\n", "  [2/3] Program:       %s (previous version: %s.previous)\n"), installExe, filepath.Base(installExe))

	if err := withService(func(s *mgr.Service) error {
		if err := s.Start(); err != nil {
			return err
		}
		return waitState(s, svc.Running, 15*time.Second)
	}); err != nil {
		return fmt.Errorf(lang.L("nowa wersja nie wystartowała: %w – przywróć %s.previous", "the new version did not start: %w – restore %s.previous"), err, installExe)
	}
	fmt.Println(lang.L("  [3/3] Usługa działa", "  [3/3] Service running"))
	return nil
}
