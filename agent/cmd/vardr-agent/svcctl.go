// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/agent/internal/guard"
	"siem/agent/internal/secure"
	"siem/internal/lang"
)

var stateNames = map[svc.State][2]string{
	svc.Stopped: {"zatrzymany", "stopped"}, svc.StartPending: {"uruchamianie", "starting"}, svc.StopPending: {"zatrzymywanie", "stopping"},
	svc.Running: {"działa", "running"}, svc.Paused: {"wstrzymany", "paused"}, svc.ContinuePending: {"wznawianie", "resuming"},
	svc.PausePending: {"wstrzymywanie", "pausing"},
}

// stateName: stan usługi w języku systemu.
func stateName(s svc.State) string {
	n := stateNames[s]
	return lang.L(n[0], n[1])
}

var errNotInstalled = lang.Errorf("agent nie jest zainstalowany (brak usługi "+serviceName+") – zainstaluj: vardr-agent install",
	"the agent is not installed (no "+serviceName+" service) – install it: vardr-agent install")

// requireAdmin zwraca czytelny błąd, gdy polecenie wymaga administratora.
func requireAdmin(what string) error {
	if secure.IsPrivileged() {
		return nil
	}
	return fmt.Errorf(lang.L("%s wymaga uprawnień administratora – uruchom PowerShell lub cmd jako administrator",
		"%s requires administrator rights – run PowerShell or cmd as administrator"), what)
}

// queryService odczytuje stan usługi z minimalnymi prawami (działa także
// bez uprawnień administratora).
func queryService() (svc.Status, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return svc.Status{}, err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return svc.Status{}, errNotInstalled
	}
	if err != nil {
		return svc.Status{}, err
	}
	s := &mgr.Service{Name: serviceName, Handle: h}
	defer s.Close()
	return s.Query()
}

// withService otwiera usługę z pełnymi prawami, a gdy usługa jest chroniona
// (administrator nie ma prawa jej zatrzymać ani usunąć) – z prawami, które
// administratorowi zostają (stan, start, polecenia agenta).
func withService(fn func(*mgr.Service) error) error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf(lang.L("brak dostępu do menedżera usług: %w", "no access to the service manager: %w"), err)
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_ALL_ACCESS)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		h, err = windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG|windows.SERVICE_START|
			windows.SERVICE_USER_DEFINED_CONTROL|windows.SERVICE_INTERROGATE)
	}
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		return errNotInstalled
	case err != nil:
		return err
	}
	s := &mgr.Service{Name: serviceName, Handle: h}
	defer s.Close()
	return fn(s)
}

// protectedErr tłumaczy odmowę dostępu przy zatrzymaniu lub usunięciu usługi.
func protectedErr(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return errors.New(lang.L("usługa agenta jest chroniona – zatrzymanie i deinstalacja wymagają tokenu z panelu "+
			"(Huginn → agent → Token deinstalacji): -token XXXXX-XXXXX-XXXXX-XXXXX",
			"the agent service is protected – stopping and uninstalling require a token from the panel "+
				"(Huginn → agent → Uninstall token): -token XXXXX-XXXXX-XXXXX-XXXXX"))
	}
	return err
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(lang.L("usługa nie osiągnęła stanu „%s” w ciągu %s (obecnie: %s) – sprawdź vardr-agent status",
				"the service did not reach the state \"%s\" within %s (now: %s) – check vardr-agent status"),
				stateName(want), timeout, stateName(st.State))
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func startService() error {
	if err := requireAdmin(lang.L("Uruchomienie agenta", "Starting the agent")); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State == svc.Running {
			fmt.Println(lang.L("Agent już działa.", "The agent is already running."))
			return nil
		}
		if err := s.Start(); err != nil {
			return err
		}
		if err := waitState(s, svc.Running, 15*time.Second); err != nil {
			return err
		}
		fmt.Println(lang.L("Agent uruchomiony.", "Agent started."))
		return nil
	})
}

func stopService(cfgPath, token string) error {
	if err := requireAdmin(lang.L("Zatrzymanie agenta", "Stopping the agent")); err != nil {
		return err
	}
	if st, err := queryService(); err == nil && st.State == svc.Stopped {
		fmt.Println(lang.L("Agent jest już zatrzymany.", "The agent is already stopped."))
		return nil
	}
	if err := authorize(cfgPath, "stop", token); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State == svc.Stopped {
			fmt.Println(lang.L("Agent jest już zatrzymany.", "The agent is already stopped."))
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return protectedErr(err)
		}
		if err := waitState(s, svc.Stopped, 30*time.Second); err != nil {
			return err
		}
		fmt.Println(lang.L("Agent zatrzymany.", "Agent stopped."))
		return nil
	})
}

// restartService uruchamia agenta ponownie w procesie usługi (polecenie
// agenta – bez zatrzymywania usługi, więc także przy włączonej ochronie).
func restartService() error {
	if err := requireAdmin(lang.L("Ponowne uruchomienie agenta", "Restarting the agent")); err != nil {
		return err
	}
	st, err := queryService()
	if err != nil {
		return err
	}
	if st.State != svc.Running {
		return startService()
	}
	if err := withService(func(s *mgr.Service) error {
		_, err := s.Control(svc.Cmd(guard.ControlRestart))
		return err
	}); err != nil {
		return fmt.Errorf(lang.L("polecenie restartu: %w", "restart command: %w"), err)
	}
	fmt.Println(lang.L("Agent uruchamia się ponownie (w procesie usługi) – stan: vardr-agent status.",
		"The agent is restarting (in the service process) – state: vardr-agent status."))
	return nil
}

// moveServiceBinary przepina istniejącą usługę na installExe, jeśli
// wskazuje inny program (aktualizacja z wersji 0.7.x: siem_agent.exe →
// vardr-agent.exe), i usuwa stary plik. Usługa musi być zatrzymana; zmiana
// konfiguracji wymaga konta SYSTEM (MSI) albo usługi bez ochrony (po tokenie).
func moveServiceBinary(cfgPath string) error {
	moved := false
	err := withService(func(s *mgr.Service) error {
		c, err := s.Config()
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(c.BinaryPathName), strings.ToLower(installExe)) {
			return nil
		}
		c.BinaryPathName = syscall.EscapeArg(installExe) + " -config " + syscall.EscapeArg(cfgPath)
		if err := s.UpdateConfig(c); err != nil {
			return protectedErr(err)
		}
		moved = true
		return nil
	})
	if err != nil {
		return fmt.Errorf(lang.L("zmiana programu usługi na %s: %w", "changing the service program to %s: %w"), installExe, err)
	}
	if moved {
		fmt.Printf(lang.L("Usługa %s uruchamia teraz %s\n", "Service %s now runs %s\n"), serviceName, installExe)
	}
	// Usługa uruchamia installExe – pozostałości wersji 0.7.x są zbędne.
	for _, old := range []string{legacyExe, legacyExe + ".previous"} {
		if fileExists(old) && !samePath(old, installExe) {
			_ = os.Remove(old)
		}
	}
	return nil
}

// registerService tworzy usługę Windows z automatycznym startem
// i restartem po awarii.
func registerService(exe, cfgPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf(lang.L("brak dostępu do menedżera usług: %w", "no access to the service manager: %w"), err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf(lang.L("usługa %s już istnieje", "service %s already exists"), serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: lang.L(serviceDescriptionPL, serviceDescriptionEN),
		StartType:   mgr.StartAutomatic,
	}, "-config", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, uint32((24 * time.Hour).Seconds()))
}

// deleteService zatrzymuje i usuwa usługę.
func deleteService() error {
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State != svc.Stopped {
			if _, err := s.Control(svc.Stop); err == nil {
				_ = waitState(s, svc.Stopped, 30*time.Second)
			} else if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				return protectedErr(err)
			}
		}
		return protectedErr(s.Delete())
	})
}
