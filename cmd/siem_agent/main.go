//go:build windows

// Command siem_agent to agent Windows zbierający zdarzenia z Event Log
// i wysyłający je po mTLS do serwera SIEM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"siem/internal/agent/config"
	"siem/internal/agent/core"
	"siem/internal/agent/limits"
	"siem/internal/agent/logging"
	"siem/internal/agent/secure"
	"siem/internal/agent/shipper"
	"siem/internal/agent/source"
	"siem/internal/agent/state"
	"siem/internal/agent/status"
	"siem/internal/agent/throttle"
	"siem/internal/agent/winevt"
)

const version = "0.3.0"

func usage() {
	fmt.Fprintf(os.Stderr, `siem_agent %s – agent SIEM dla Windows

Instalacja (PowerShell lub cmd jako administrator, w folderze z siem_agent.exe,
ca.crt, agent.crt i agent.key):
  siem_agent install [-server adres] [-profile workstation|server|dc] [-start-at now|oldest] [-no-start]
      -server   adres serwera, np. 192.168.88.98 lub siem.firma.local:8443 (bez -server: pytanie)
      -profile  zestaw zbieranych zdarzeń (domyślnie workstation)
      -ca, -cert, -key   inne położenie certyfikatów

Sterowanie (po instalacji polecenie działa z każdego miejsca):
  siem_agent status                 stan usługi, połączenia, kanałów i limitów
  siem_agent start | stop | restart
  siem_agent test                   sprawdzenie połączenia z serwerem
  siem_agent set-server <adres>     zmiana adresu serwera (restartuje agenta)
  siem_agent uninstall [-purge]     odinstalowanie (-purge: także dane i certyfikaty)

Diagnostyka:
  siem_agent check                  walidacja konfiguracji, certyfikatów i uprawnień
  siem_agent run                    uruchomienie w konsoli zamiast usługi (Ctrl+C kończy)
  siem_agent version

Opcja -config <plik> (przed lub po poleceniu) wskazuje inną konfigurację.
Domyślnie: %s (po instalacji) lub agent.yaml obok programu.
`, version, installCfg)
}

// defaultConfigPath: konfiguracja zainstalowanego agenta, a jeśli jej nie ma –
// agent.yaml obok programu (uruchamianie z folderu, laboratorium).
func defaultConfigPath() string {
	if _, err := os.Stat(installCfg); err == nil || errors.Is(err, fs.ErrPermission) {
		return installCfg
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "agent.yaml")
}

func main() {
	global := flag.NewFlagSet("siem_agent", flag.ExitOnError)
	global.Usage = usage
	cfgFlag := global.String("config", "", "plik konfiguracji")
	_ = global.Parse(os.Args[1:])

	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		path := *cfgFlag
		if path == "" {
			path = defaultConfigPath()
		}
		runService(path)
		return
	}

	args := global.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	cf := flag.NewFlagSet(cmd, flag.ExitOnError)
	cf.Usage = usage
	cfgPath := cf.String("config", *cfgFlag, "plik konfiguracji")
	var opts installOptions
	purge := new(bool)
	switch cmd {
	case "install":
		cf.StringVar(&opts.server, "server", "", "adres serwera")
		cf.StringVar(&opts.profile, "profile", "workstation", "profil zdarzeń")
		cf.StringVar(&opts.startAt, "start-at", "now", "now | oldest")
		cf.StringVar(&opts.ca, "ca", "", "plik CA")
		cf.StringVar(&opts.cert, "cert", "", "certyfikat agenta")
		cf.StringVar(&opts.key, "key", "", "klucz agenta")
		cf.BoolVar(&opts.noStart, "no-start", false, "nie uruchamiaj usługi po instalacji")
	case "uninstall":
		purge = cf.Bool("purge", false, "usuń także dane, konfigurację i certyfikaty")
	}
	_ = cf.Parse(rest)
	if *cfgPath == "" {
		*cfgPath = defaultConfigPath()
	}

	var err error
	switch cmd {
	case "install":
		err = install(opts)
	case "uninstall":
		err = uninstall(*purge)
	case "start":
		err = startService()
	case "stop":
		err = stopService()
	case "restart":
		err = restartService()
	case "status":
		err = showStatus(*cfgPath)
	case "test":
		err = testConnection(*cfgPath)
	case "set-server":
		if cf.NArg() != 1 {
			err = errors.New("użycie: siem_agent set-server <adres>, np. siem_agent set-server 192.168.88.98")
		} else {
			err = setServer(*cfgPath, cf.Arg(0))
		}
	case "check":
		err = check(*cfgPath)
	case "run":
		err = runConsole(*cfgPath)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help", "/?":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "nieznane polecenie %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func runConsole(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	level, _ := logging.Level(cfg.Logging.Level)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAgent(ctx, cfg, log)
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
	fmt.Printf("  limity:    %s\n", formatKV(limitAttrs(cfg.Limits)))
	fmt.Printf("  klucz:     %s – %s\n", cfg.Server.KeyFile, protection(cfg.Server.KeyFile))
	exe, _ := os.Executable()
	if ok, why := secure.ServiceBinarySafe(exe); ok {
		fmt.Printf("  program:   %s – chroniony przed zapisem przez zwykłych użytkowników\n", exe)
	} else {
		fmt.Printf("  program:   UWAGA – %s\n             (usługa uruchomiona z tego miejsca pozwoliłaby podmienić program działający jako SYSTEM)\n", why)
	}
	if _, err := os.Stat(cfg.StateDir); err == nil {
		fmt.Printf("  stan:      %s – %s\n", cfg.StateDir, protection(cfg.StateDir))
	}
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

func protection(path string) string {
	ok, why, err := secure.IsRestricted(path)
	switch {
	case err != nil:
		return "nie można sprawdzić uprawnień: " + err.Error()
	case ok:
		return "chroniony (tylko SYSTEM i Administratorzy)"
	default:
		return "UWAGA: " + why
	}
}

// protectFiles zawęża uprawnienia katalogu stanu i klucza prywatnego.
// Zwraca ostrzeżenia do pokazania w statusie.
func protectFiles(cfg *config.Config, log *slog.Logger) []string {
	if !secure.IsPrivileged() {
		w := "agent działa bez uprawnień administratora – uprawnienia katalogu stanu i klucza nie zostały zawężone"
		log.Warn(w)
		return []string{w}
	}
	var warns []string
	if err := secure.RestrictDir(cfg.StateDir); err != nil {
		warns = append(warns, err.Error())
	}
	if err := secure.RestrictFile(cfg.Server.KeyFile); err != nil {
		warns = append(warns, err.Error())
	}
	for _, w := range warns {
		log.Error("nie udało się zabezpieczyć plików agenta", "err", w)
	}
	return warns
}

// runAgent buduje komponenty z konfiguracji i uruchamia rdzeń agenta.
func runAgent(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("katalog stanu: %w", err)
	}
	warnings := protectFiles(cfg, log)
	runtime.GOMAXPROCS(cfg.Limits.MaxProcs)

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

	tracker := status.NewTracker(version, agentID, cfg.Server.URL, limitMap(cfg.Limits))
	privileged := secure.IsPrivileged()
	if exe, err := os.Executable(); err == nil && privileged {
		if ok, why := secure.ServiceBinarySafe(exe); !ok {
			msg := "plik programu agenta może zostać podmieniony przez zwykłego użytkownika – ryzyko eskalacji uprawnień: " + why
			log.Error(msg)
			tracker.Warn(msg)
		}
	}

	// Stan: plik w state_dir + kopia w rejestrze (znacznik wcześniejszego działania).
	backup := state.NewRegistryBackup(privileged, cfg.StateDir)
	store := state.NewStore(cfg.StateDir)
	store.Backup = backup
	store.OnRecreate = func(dir string) error {
		msg := "katalog stanu agenta został usunięty – utworzono go ponownie (możliwa manipulacja)"
		log.Error(msg, "dir", dir)
		tracker.Warn(msg)
		if privileged {
			return secure.RestrictDir(dir)
		}
		return nil
	}
	log.Info("kopia stanu agenta", "location", backup.Location())
	tracker.AddProbe(func(s *status.Status) {
		s.Warnings = append(s.Warnings, warnings...)
		s.Process.CPUTime = processCPUTime()
	})

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
	sender.AttachStatus(tracker)

	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     cfg.Batch.MaxEvents,
		MaxBytes:      cfg.Batch.MaxBytes,
		MaxEventBytes: cfg.Batch.MaxEventBytes,
		FlushInterval: cfg.Batch.FlushInterval,
		Filters:       filters,
		RetryDelay:    retryDelay,
		MaxEPS:        cfg.Limits.MaxEPS,
		Status:        tracker,
		ClassifyError: classifyError,
	}, sources, sender, store, log)

	statusCtx, stopStatus := context.WithCancel(context.Background())
	statusDone := make(chan struct{})
	go func() {
		tracker.Run(statusCtx, cfg.StateDir, 5*time.Second)
		close(statusDone)
	}()

	log.Info("agent uruchomiony", "version", version, "eventlog", true)
	err = agent.Run(ctx)
	stopStatus()
	<-statusDone

	s := sender.Stats
	log.Info("agent zatrzymany", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load(),
		"retries", s.Retries.Load(), "events_quarantined", s.EventsQuarantined.Load(), "eventlog", true)
	return err
}

func showStatus(cfgPath string) error {
	st, err := queryService()
	switch {
	case errors.Is(err, errNotInstalled):
		fmt.Println("Usługa SiemAgent: nie jest zainstalowana")
	case err != nil:
		fmt.Printf("Usługa SiemAgent: nie można sprawdzić (%v)\n", err)
	default:
		fmt.Printf("Usługa SiemAgent: %s", stateNames[st.State])
		if st.ProcessId != 0 {
			fmt.Printf(" (PID %d)", st.ProcessId)
		}
		fmt.Println()
	}

	cfg, err := config.Load(cfgPath)
	if errors.Is(err, fs.ErrPermission) {
		fmt.Println("\nSzczegóły (połączenie, kanały, liczniki) są dostępne tylko dla administratora –")
		fmt.Println("uruchom PowerShell lub cmd jako administrator.")
		return nil
	}
	if err != nil {
		return err
	}
	p := filepath.Join(cfg.StateDir, status.FileName)
	s, err := status.Read(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("brak pliku statusu %s – agent jeszcze nie był uruchomiony z tą konfiguracją", p)
	case errors.Is(err, fs.ErrPermission):
		fmt.Println("\nSzczegóły są dostępne tylko dla administratora – uruchom PowerShell lub cmd jako administrator.")
		return nil
	case err != nil:
		return err
	}
	fmt.Println()
	status.Render(os.Stdout, s, time.Now())
	return nil
}

// limitAttrs opisuje limity w logach (0 = brak limitu).
func limitAttrs(l config.LimitsConfig) []any {
	return []any{"priority", l.Priority, "cpu_max_percent", l.CPUMaxPercent,
		"memory_soft_mb", *l.MemorySoftMB, "memory_hard_mb", *l.MemoryHardMB,
		"max_eps", l.MaxEPS, "max_send_kbps", l.MaxSendKBps, "max_procs", l.MaxProcs}
}

// formatKV zamienia pary klucz–wartość na tekst "k=v k=v".
func formatKV(attrs []any) string {
	parts := make([]string, 0, len(attrs)/2)
	for i := 0; i+1 < len(attrs); i += 2 {
		parts = append(parts, fmt.Sprintf("%v=%v", attrs[i], attrs[i+1]))
	}
	return strings.Join(parts, " ")
}

func limitMap(l config.LimitsConfig) map[string]any {
	attrs := limitAttrs(l)
	m := make(map[string]any, len(attrs)/2)
	for i := 0; i+1 < len(attrs); i += 2 {
		m[attrs[i].(string)] = attrs[i+1]
	}
	return m
}

// retryDelay: brakujący kanał (np. Sysmon niezainstalowany) i brak uprawnień
// sprawdzamy rzadko; inne błędy szybciej.
func retryDelay(err error) time.Duration {
	if errors.Is(err, winevt.ErrChannelNotFound) || errors.Is(err, winevt.ErrAccessDenied) {
		return 5 * time.Minute
	}
	return 10 * time.Second
}

func classifyError(err error) string {
	switch {
	case errors.Is(err, winevt.ErrChannelNotFound):
		return status.ChannelNotFound
	case errors.Is(err, winevt.ErrAccessDenied):
		return status.ChannelAccessDenied
	default:
		return status.ChannelError
	}
}

func processCPUTime() time.Duration {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return 0
	}
	// Filetime dla czasów procesu to liczba interwałów 100 ns.
	return time.Duration((filetimeTicks(k) + filetimeTicks(u)) * 100)
}

func filetimeTicks(f windows.Filetime) int64 {
	return int64(f.HighDateTime)<<32 | int64(f.LowDateTime)
}
