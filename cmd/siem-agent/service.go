//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/internal/agent/config"
)

const (
	serviceName        = "SiemAgent"
	serviceDisplayName = "SIEM Agent"
	serviceDescription = "Zbiera zdarzenia z Windows Event Log i wysyła je szyfrowanym kanałem (mTLS) do serwera SIEM."
)

type agentService struct {
	cfgPath string
	log     *slog.Logger
}

func runService(cfgPath string) {
	// Katalog logu: state_dir z konfiguracji, a jeśli konfiguracja jest
	// błędna – katalog domyślny, żeby błąd i tak trafił do pliku.
	logDir := filepath.Join(os.Getenv("ProgramData"), "SiemAgent")
	if cfg, err := config.Load(cfgPath); err == nil {
		logDir = cfg.StateDir
	}
	w, err := openLogFile(logDir)
	if err != nil {
		os.Exit(1)
	}
	defer w.Close()
	log := slog.New(slog.NewTextHandler(w, nil))

	if err := svc.Run(serviceName, &agentService{cfgPath: cfgPath, log: log}); err != nil {
		log.Error("usługa zakończona błędem", "err", err)
	}
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, s.cfgPath, s.log) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.log.Info("otrzymano polecenie zatrzymania usługi")
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					s.log.Warn("agent nie zakończył się w ciągu 20 s")
				}
				return false, 0
			}
		case err := <-done:
			// Agent zakończył się sam (np. błąd konfiguracji). Niezerowy kod
			// wyjścia uruchamia akcje odzyskiwania (restart usługi).
			s.log.Error("agent zakończył działanie", "err", err)
			return false, 1
		}
	}
}

func installService(cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	if _, err := config.Load(absCfg); err != nil {
		return fmt.Errorf("konfiguracja niepoprawna, usługa nie zostanie zainstalowana: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("brak dostępu do menedżera usług (uruchom jako administrator): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("usługa %s już istnieje", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      serviceDisplayName,
		Description:      serviceDescription,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: false,
	}, "-config", absCfg)
	if err != nil {
		return err
	}
	defer s.Close()

	// Automatyczny restart po awarii (roadmapa, sekcja 7).
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, uint32((24 * time.Hour).Seconds()))
	if err != nil {
		return fmt.Errorf("usługa utworzona, ale nie ustawiono akcji odzyskiwania: %w", err)
	}
	fmt.Printf("Usługa %s zainstalowana (konfiguracja: %s). Uruchom: siem-agent start\n", serviceName, absCfg)
	return nil
}

func withService(fn func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("brak dostępu do menedżera usług (uruchom jako administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("usługa %s nie jest zainstalowana: %w", serviceName, err)
	}
	defer s.Close()
	return fn(s)
}

func startService() error {
	return withService(func(s *mgr.Service) error { return s.Start() })
}

func stopService() error {
	return withService(func(s *mgr.Service) error {
		st, err := s.Control(svc.Stop)
		if err != nil {
			return err
		}
		for deadline := time.Now().Add(30 * time.Second); st.State != svc.Stopped; {
			if time.Now().After(deadline) {
				return errors.New("usługa nie zatrzymała się w ciągu 30 s")
			}
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return err
			}
		}
		return nil
	})
}

func serviceStatus() error {
	return withService(func(s *mgr.Service) error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		names := map[svc.State]string{
			svc.Stopped: "zatrzymana", svc.StartPending: "uruchamianie", svc.StopPending: "zatrzymywanie",
			svc.Running: "działa", svc.Paused: "wstrzymana",
		}
		fmt.Printf("%s: %s (PID %d)\n", serviceName, names[st.State], st.ProcessId)
		return nil
	})
}

// uninstallService usuwa usługę. Ochrona tokenem deinstalacji jest
// zaplanowana w etapie 8 roadmapy.
func uninstallService() error {
	err := stopService()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		fmt.Fprintln(os.Stderr, "uwaga:", err)
	}
	return withService(func(s *mgr.Service) error {
		if err := s.Delete(); err != nil {
			return err
		}
		fmt.Printf("Usługa %s usunięta.\n", serviceName)
		return nil
	})
}
