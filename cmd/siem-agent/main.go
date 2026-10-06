//go:build windows

// Command siem-agent to agent Windows zbierający zdarzenia z Event Log
// i wysyłający je po mTLS do serwera SIEM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"siem/internal/agent/config"
	"siem/internal/agent/core"
	"siem/internal/agent/limits"
	"siem/internal/agent/shipper"
	"siem/internal/agent/source"
	"siem/internal/agent/state"
	"siem/internal/agent/throttle"
	"siem/internal/agent/winevt"
)

const version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `siem-agent %s

Użycie:
  siem-agent [-config plik] run        uruchomienie w konsoli (Ctrl+C kończy)
  siem-agent [-config plik] install    instalacja usługi Windows (wymaga administratora)
  siem-agent uninstall                 usunięcie usługi
  siem-agent start | stop | status     sterowanie usługą
  siem-agent [-config plik] check      walidacja konfiguracji i certyfikatów
  siem-agent version

Domyślny plik konfiguracji: agent.yaml obok pliku wykonywalnego.
`, version)
}

func main() {
	exe, _ := os.Executable()
	cfgPath := flag.String("config", filepath.Join(filepath.Dir(exe), "agent.yaml"), "plik konfiguracji")
	flag.Usage = usage
	flag.Parse()

	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runService(*cfgPath)
		return
	}

	var err error
	switch cmd := flag.Arg(0); cmd {
	case "run":
		err = runConsole(*cfgPath)
	case "check":
		err = check(*cfgPath)
	case "install":
		err = installService(*cfgPath)
	case "uninstall":
		err = uninstallService()
	case "start":
		err = startService()
	case "stop":
		err = stopService()
	case "status":
		err = serviceStatus()
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func runConsole(cfgPath string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAgent(ctx, cfgPath, log)
}

func check(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	_, agentID, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, cfg.Server.Timeout)
	if err != nil {
		return err
	}
	fmt.Printf("Konfiguracja poprawna.\n  agent_id:  %s\n  serwer:    %s\n  state_dir: %s\n", agentID, cfg.Server.URL, cfg.StateDir)
	for _, ch := range cfg.Channels {
		q, agentSide := winevt.BuildQuery(ch.EventIDs)
		mode := "filtr w zapytaniu XPath"
		if agentSide {
			mode = "filtr po stronie agenta (lista za długa dla XPath)"
		}
		fmt.Printf("  kanał %-45s %s\n    %s\n", ch.Name, mode, q)
	}
	return nil
}

// runAgent buduje komponenty z konfiguracji i uruchamia rdzeń agenta.
func runAgent(ctx context.Context, cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("katalog stanu: %w", err)
	}

	client, agentID, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, cfg.Server.Timeout)
	if err != nil {
		return err
	}
	log = log.With("agent_id", agentID)

	// Kaganiec nakładany przed rozpoczęciem odczytu.
	lim, err := limits.Apply(cfg.Limits.Resource())
	if err != nil {
		return fmt.Errorf("limity zasobów: %w", err)
	}
	defer lim.Close()
	log.Info("limity zasobów aktywne", limitAttrs(cfg.Limits)...)

	var sources []source.Source
	filters := map[string]map[uint32]bool{}
	for _, ch := range cfg.Channels {
		q, agentSide := winevt.BuildQuery(ch.EventIDs)
		if agentSide {
			allowed := map[uint32]bool{}
			for _, id := range ch.EventIDs {
				allowed[id] = true
			}
			filters[ch.Name] = allowed
			log.Warn("lista Event ID za długa dla XPath – filtr po stronie agenta", "channel", ch.Name, "ids", len(ch.EventIDs))
		}
		sources = append(sources, winevt.NewReader(ch.Name, q, cfg.StartAt, log))
	}

	sender := shipper.NewHTTPSender(client, cfg.Server.URL, filepath.Join(cfg.StateDir, "quarantine"), log)
	if kbps := cfg.Limits.MaxSendKBps; kbps > 0 {
		sender.Bandwidth = throttle.New(float64(kbps)*1024, float64(kbps)*1024)
	}
	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     cfg.Batch.MaxEvents,
		MaxBytes:      cfg.Batch.MaxBytes,
		FlushInterval: cfg.Batch.FlushInterval,
		Filters:       filters,
		RetryDelay:    retryDelay,
		MaxEPS:        cfg.Limits.MaxEPS,
	}, sources, sender, state.NewStore(cfg.StateDir), log)

	err = agent.Run(ctx)
	s := sender.Stats
	log.Info("agent zatrzymany", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load(),
		"retries", s.Retries.Load(), "events_quarantined", s.EventsQuarantined.Load())
	return err
}

// limitAttrs opisuje limity w logach (0 = brak limitu).
func limitAttrs(l config.LimitsConfig) []any {
	return []any{"priority", l.Priority, "cpu_max_percent", l.CPUMaxPercent,
		"memory_soft_mb", *l.MemorySoftMB, "memory_hard_mb", *l.MemoryHardMB,
		"max_eps", l.MaxEPS, "max_send_kbps", l.MaxSendKBps}
}

// retryDelay: brakujący kanał (np. Sysmon niezainstalowany) i brak uprawnień
// sprawdzamy rzadko; inne błędy szybciej.
func retryDelay(err error) time.Duration {
	if errors.Is(err, winevt.ErrChannelNotFound) || errors.Is(err, winevt.ErrAccessDenied) {
		return 5 * time.Minute
	}
	return 10 * time.Second
}

// openLogFile otwiera plik logu usługi; przy rozmiarze > 10 MiB poprzedni
// plik jest przenoszony do agent.log.1 (prosta rotacja przy starcie).
func openLogFile(dir string) (io.WriteCloser, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "agent.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 10<<20 {
		_ = os.Rename(p, p+".1")
	}
	return os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
