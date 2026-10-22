// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"siem/agent/internal/guard"
	"siem/agent/internal/logging"
)

const (
	serviceName        = "SiemAgent"
	serviceDisplayName = "SIEM Agent"
	serviceDescription = "Zbiera zdarzenia z Windows Event Log i wysyła je szyfrowanym kanałem (mTLS) do serwera SIEM."
)

type agentService struct {
	cfgPath string
	cfg     *config.Config
	cfgErr  error
	log     *slog.Logger
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

	if err := svc.Run(serviceName, &agentService{cfgPath: cfgPath, cfg: cfg, cfgErr: cfgErr, log: log}); err != nil {
		log.Error("usługa zakończona błędem", "err", err)
	}
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	if s.cfgErr != nil {
		return false, 1 // niezerowy kod: akcje odzyskiwania ponowią start
	}

	// Ochrona agenta: wykrycie zabicia poprzedniego procesu, pilnowanie
	// uprawnień usługi (w runAgent) i powód zatrzymania.
	g := newGuardian(s.cfg.StateDir, s.log)
	g.startup()
	svcGuard = g
	defer g.cleanExit()

	var cancel context.CancelFunc
	done := make(chan error, 1)
	start := func(cfg *config.Config) {
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		go func() { done <- runAgent(ctx, cfg, s.log) }()
	}
	stop := func() bool {
		cancel()
		select {
		case <-done:
			return true
		case <-time.After(20 * time.Second):
			s.log.Warn("agent nie zakończył się w ciągu 20 s")
			return false
		}
	}
	start(s.cfg)

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				reason := "shutdown"
				if c.Cmd == svc.Stop {
					reason = g.stopReason()
				}
				g.setStopping(reason)
				s.log.Info("otrzymano polecenie zatrzymania usługi", "reason", reason)
				status <- svc.Status{State: svc.StopPending}
				stop()
				return false, 0
			case guard.ControlRestart:
				// vardr-agent restart / set-server: ponowne uruchomienie w procesie
				// usługi (chroniona usługa nie pozwala administratorowi jej zatrzymać).
				cfg, err := config.Load(s.cfgPath)
				if err != nil {
					s.log.Error("restart agenta: konfiguracja niepoprawna – zostaje bieżąca", "err", err, "eventlog", true)
					continue
				}
				s.log.Info("polecenie restartu agenta", "eventlog", true)
				if !stop() {
					return false, 1 // zawieszony agent – akcje odzyskiwania uruchomią usługę ponownie
				}
				start(cfg)
			}
		case err := <-done:
			// Agent zakończył się sam (np. błąd konfiguracji). Niezerowy kod
			// wyjścia uruchamia akcje odzyskiwania (restart usługi).
			s.log.Error("agent zakończył działanie", "err", err)
			return false, 1
		}
	}
}
