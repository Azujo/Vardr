//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/internal/agent/secure"
)

var stateNames = map[svc.State]string{
	svc.Stopped: "zatrzymany", svc.StartPending: "uruchamianie", svc.StopPending: "zatrzymywanie",
	svc.Running: "działa", svc.Paused: "wstrzymany", svc.ContinuePending: "wznawianie", svc.PausePending: "wstrzymywanie",
}

var errNotInstalled = errors.New("agent nie jest zainstalowany (brak usługi " + serviceName + ") – zainstaluj: siem_agent install")

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

func withService(fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("brak dostępu do menedżera usług: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errNotInstalled
	}
	defer s.Close()
	return fn(s)
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
			return fmt.Errorf("usługa nie osiągnęła stanu „%s” w ciągu %s (obecnie: %s) – sprawdź siem_agent status",
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

func stopService() error {
	if err := requireAdmin("Zatrzymanie agenta"); err != nil {
		return err
	}
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State == svc.Stopped {
			fmt.Println("Agent jest już zatrzymany.")
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
		if err := waitState(s, svc.Stopped, 30*time.Second); err != nil {
			return err
		}
		fmt.Println("Agent zatrzymany.")
		return nil
	})
}

func restartService() error {
	if err := stopService(); err != nil && !errors.Is(err, errNotInstalled) {
		return err
	}
	return startService()
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
			}
		}
		return s.Delete()
	})
}
