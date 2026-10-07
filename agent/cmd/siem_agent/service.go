//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"siem/agent/internal/config"
	"siem/agent/internal/logging"
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
