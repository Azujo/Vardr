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
	"siem/internal/agent/logging"
	"siem/internal/agent/secure"
)

const (
	serviceName        = "SiemAgent"
	serviceDisplayName = "SIEM Agent"
	serviceDescription = "Zbiera zdarzenia z Windows Event Log i wysyła je szyfrowanym kanałem (mTLS) do serwera SIEM."
)

type agentService struct {
	cfg    *config.Config
	cfgErr error
	log    *slog.Logger
}

func runService(cfgPath string) {
	// Log: rotowany plik w state_dir oraz ostrzeżenia i błędy w dzienniku
	// Application (źródło SiemAgent). Przy błędnej konfiguracji – katalog
	// domyślny, żeby błąd i tak został zapisany.
	cfg, cfgErr := config.Load(cfgPath)
	logDir := filepath.Join(os.Getenv("ProgramData"), "SiemAgent")
	level, maxMB, keep := slog.LevelInfo, 10, 3
	if cfgErr == nil {
		logDir = cfg.StateDir
		level, _ = logging.Level(cfg.Logging.Level)
		maxMB, keep = cfg.Logging.MaxSizeMB, cfg.Logging.MaxFiles
	}
	_ = os.MkdirAll(logDir, 0o700)
	w, err := logging.OpenRotating(filepath.Join(logDir, "agent.log"), int64(maxMB)<<20, keep)
	if err != nil {
		os.Exit(1)
	}
	defer w.Close()

	handlers := logging.Tee{slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})}
	if el, err := logging.OpenEventSink(serviceName); err == nil {
		defer el.Close()
		handlers = append(handlers, logging.NewSinkHandler(el, 10*time.Minute))
	}
	log := slog.New(handlers)
	if cfgErr != nil {
		log.Error("błędna konfiguracja agenta", "config", cfgPath, "err", cfgErr)
	}

	if err := svc.Run(serviceName, &agentService{cfg: cfg, cfgErr: cfgErr, log: log}); err != nil {
		log.Error("usługa zakończona błędem", "err", err)
	}
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	if s.cfgErr != nil {
		return false, 1 // niezerowy kod: akcje odzyskiwania ponowią start
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, s.cfg, s.log) }()

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

func installService(cfgPath string, allowUnsafe bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Usługa działa jako SYSTEM: jeśli zwykły użytkownik może podmienić plik
	// programu (lub jego folder), uzyska uprawnienia SYSTEM.
	if ok, why := secure.ServiceBinarySafe(exe); !ok {
		if !allowUnsafe {
			return fmt.Errorf("odmowa instalacji – %s\n"+
				"Skopiuj program do folderu dostępnego do zapisu tylko dla administratorów, np. %s,\n"+
				"albo (wyłącznie w laboratorium) użyj -allow-unsafe-path", why, `C:\Program Files\SiemAgent`)
		}
		fmt.Fprintln(os.Stderr, "UWAGA: instalacja z niebezpiecznej lokalizacji (-allow-unsafe-path):", why)
	}
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(absCfg)
	if err != nil {
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
	if err := logging.InstallEventSource(serviceName); err != nil {
		fmt.Fprintln(os.Stderr, "uwaga: nie zarejestrowano źródła w dzienniku zdarzeń:", err)
	}
	// Zabezpieczenie plików już przy instalacji (agent powtarza to przy każdym starcie).
	if err := os.MkdirAll(cfg.StateDir, 0o700); err == nil {
		if err := secure.RestrictDir(cfg.StateDir); err != nil {
			fmt.Fprintln(os.Stderr, "uwaga:", err)
		}
	}
	if err := secure.RestrictFile(cfg.Server.KeyFile); err != nil {
		fmt.Fprintln(os.Stderr, "uwaga:", err)
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
		_ = logging.RemoveEventSource(serviceName)
		fmt.Printf("Usługa %s usunięta.\n", serviceName)
		return nil
	})
}
