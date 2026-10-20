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
)

var stateNames = map[svc.State]string{
	svc.Stopped: "zatrzymany", svc.StartPending: "uruchamianie", svc.StopPending: "zatrzymywanie",
	svc.Running: "działa", svc.Paused: "wstrzymany", svc.ContinuePending: "wznawianie", svc.PausePending: "wstrzymywanie",
}

var errNotInstalled = errors.New("agent nie jest zainstalowany (brak usługi " + serviceName + ") – zainstaluj: vardr-agent install")

// requireAdmin zwraca czytelny błąd, gdy polecenie wymaga administratora.
func requireAdmin(what string) error {
	if secure.IsPrivileged() {
		return nil
	}
	return fmt.Errorf("%s wymaga uprawnień administratora – uruchom PowerShell lub cmd jako administrator", what)
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
		return fmt.Errorf("brak dostępu do menedżera usług: %w", err)
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
		return errors.New("usługa agenta jest chroniona – zatrzymanie i deinstalacja wymagają tokenu z panelu " +
			"(Huginn → agent → Token deinstalacji): -token XXXXX-XXXXX-XXXXX-XXXXX")
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
			return fmt.Errorf("usługa nie osiągnęła stanu „%s” w ciągu %s (obecnie: %s) – sprawdź vardr-agent status",
				stateNames[want], timeout, stateNames[st.State])
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func startService() error {
	if err := requireAdmin("Uruchomienie agenta"); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State == svc.Running {
			fmt.Println("Agent już działa.")
			return nil
		}
		if err := s.Start(); err != nil {
			return err
		}
		if err := waitState(s, svc.Running, 15*time.Second); err != nil {
			return err
		}
		fmt.Println("Agent uruchomiony.")
		return nil
	})
}

func stopService(cfgPath, token string) error {
	if err := requireAdmin("Zatrzymanie agenta"); err != nil {
		return err
	}
	if st, err := queryService(); err == nil && st.State == svc.Stopped {
		fmt.Println("Agent jest już zatrzymany.")
		return nil
	}
	if err := authorize(cfgPath, "stop", token); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State == svc.Stopped {
			fmt.Println("Agent jest już zatrzymany.")
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return protectedErr(err)
		}
		if err := waitState(s, svc.Stopped, 30*time.Second); err != nil {
			return err
		}
		fmt.Println("Agent zatrzymany.")
		return nil
	})
}

// restartService uruchamia agenta ponownie w procesie usługi (polecenie
// agenta – bez zatrzymywania usługi, więc także przy włączonej ochronie).
func restartService() error {
	if err := requireAdmin("Ponowne uruchomienie agenta"); err != nil {
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
		return fmt.Errorf("polecenie restartu: %w", err)
	}
	fmt.Println("Agent uruchamia się ponownie (w procesie usługi) – stan: vardr-agent status.")
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
		return fmt.Errorf("zmiana programu usługi na %s: %w", installExe, err)
	}
	if moved {
		fmt.Printf("Usługa %s uruchamia teraz %s\n", serviceName, installExe)
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
		return fmt.Errorf("brak dostępu do menedżera usług: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("usługa %s już istnieje", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
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
