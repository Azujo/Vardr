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
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"siem/agent/internal/config"
	"siem/agent/internal/core"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/limits"
	"siem/agent/internal/logging"
	"siem/agent/internal/logwatch"
	"siem/agent/internal/managed"
	"siem/agent/internal/secure"
	"siem/agent/internal/shipper"
	"siem/agent/internal/source"
	"siem/agent/internal/spool"
	"siem/agent/internal/state"
	"siem/agent/internal/status"
	"siem/agent/internal/sysmon"
	"siem/agent/internal/timesync"
	"siem/agent/internal/winevt"
	"siem/internal/contract"
	"siem/internal/throttle"
)

const version = "0.7.4"

func usage() {
	fmt.Fprintf(os.Stderr, `siem_agent %s – agent SIEM dla Windows

Instalacja (PowerShell lub cmd jako administrator, w folderze z siem_agent.exe,
ca.crt, agent.crt i agent.key):
  siem_agent install [-server adres] [-token token] [-profile workstation|server|dc] [-start-at now|oldest] [-no-start]
      -server   adres serwera, np. 192.168.88.98 lub siem.firma.local:8443 (bez -server: pytanie)
      -profile  zestaw zbieranych zdarzeń (domyślnie workstation)
      -token    token rejestracyjny z panelu (Bifröst) – agent sam wygeneruje klucz i pobierze
                certyfikat; w paczce z panelu token jest w pliku token.txt
      -ca, -cert, -key   inne położenie certyfikatów

Sterowanie (po instalacji polecenie działa z każdego miejsca):
  siem_agent status                 stan usługi, połączenia, kanałów, limitów i ochrony
  siem_agent start | restart
  siem_agent stop [-token T]        zatrzymanie (agent chroniony: token z panelu)
  siem_agent test                   sprawdzenie połączenia z serwerem
  siem_agent set-server <adres>     zmiana adresu serwera (restartuje agenta)
  siem_agent upgrade [-token T]     aktualizacja programu (uruchom z folderu nowej wersji)
  siem_agent uninstall [-token T] [-purge]
                                    odinstalowanie (-purge: także dane i certyfikaty)

Ochrona: agent w grupie z włączoną ochroną (domyślnie) ma usługę, której
administrator nie zatrzyma ani nie usunie bez jednorazowego tokenu z panelu
(Huginn → agent → Token deinstalacji). Próby bez tokenu panel zgłasza jako alert.

Diagnostyka:
  siem_agent check                  walidacja konfiguracji, certyfikatów i uprawnień
  siem_agent run                    uruchomienie w konsoli zamiast usługi (Ctrl+C kończy)
  siem_agent enroll -server <adres> -token <token> -dir <katalog>
                                    rejestracja bez instalacji usługi (test, konsola)
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
	var eo enrollOptions
	purge := new(bool)
	var token, upgradeCode string
	switch cmd {
	case "stop", "upgrade":
		cf.StringVar(&token, "token", "", "token deinstalacji z panelu (agent chroniony)")
	case "msi-uninstall":
		cf.StringVar(&token, "token", "", "token deinstalacji (właściwość UNINSTALL_TOKEN instalatora MSI)")
		cf.StringVar(&upgradeCode, "upgrade", "", "kod produktu aktualizującego (UPGRADINGPRODUCTCODE – aktualizacja, nie deinstalacja)")
	case "install":
		cf.StringVar(&opts.server, "server", "", "adres serwera")
		cf.StringVar(&opts.profile, "profile", "", "profil zdarzeń (domyślnie z tokenu albo workstation)")
		cf.StringVar(&opts.token, "token", "", "token rejestracyjny z panelu (zamiast certyfikatu w paczce)")
		cf.StringVar(&opts.panel, "panel", "", "adres panelu do rejestracji (domyślnie https://<serwer>:8444)")
		cf.StringVar(&opts.startAt, "start-at", "now", "now | oldest")
		cf.StringVar(&opts.ca, "ca", "", "plik CA")
		cf.StringVar(&opts.cert, "cert", "", "certyfikat agenta")
		cf.StringVar(&opts.key, "key", "", "klucz agenta")
		cf.BoolVar(&opts.noStart, "no-start", false, "nie uruchamiaj usługi po instalacji")
	case "msi-install":
		cf.StringVar(&opts.server, "server", "", "adres serwera (właściwość SERVER instalatora MSI)")
		cf.StringVar(&opts.token, "token", "", "token rejestracyjny (właściwość TOKEN instalatora MSI)")
	case "uninstall":
		purge = cf.Bool("purge", false, "usuń także dane, konfigurację i certyfikaty")
		cf.StringVar(&token, "token", "", "token deinstalacji z panelu (agent chroniony)")
	case "enroll":
		cf.StringVar(&eo.server, "server", "", "adres serwera")
		cf.StringVar(&eo.token, "token", "", "token rejestracyjny z panelu")
		cf.StringVar(&eo.ca, "ca", "", "plik głównego CA (domyślnie ca.crt obok programu)")
		cf.StringVar(&eo.panel, "panel", "", "adres panelu (domyślnie https://<serwer>:8444)")
		cf.StringVar(&eo.dir, "dir", "", "katalog na certyfikaty i agent.yaml")
		cf.StringVar(&eo.profile, "profile", "", "profil zdarzeń (domyślnie z tokenu)")
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
		err = uninstall(*cfgPath, *purge, token)
	case "upgrade":
		err = upgrade(*cfgPath, token)
	case "msi-install":
		// Wypełniacze z instalatora bez podmiany (aktualizacja bazowym MSI) – jak brak wartości.
		err = msiInstall(contract.MSIValue(opts.server), contract.MSIValue(opts.token))
	case "msi-uninstall":
		err = msiUninstall(token, upgradeCode)
	case "enroll":
		err = enrollOnly(eo)
	case "start":
		err = startService()
	case "stop":
		if isSystem() {
			err = installerStop(*cfgPath) // instalator MSI (stop poprzedniej instalacji bez MSI)
		} else {
			err = stopService(*cfgPath, token)
		}
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

	client, certs, err := shipper.NewReloadableTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, cfg.Server.Timeout)
	if err != nil {
		return err
	}
	agentID := certs.AgentID()
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

	g := svcGuard
	if g != nil {
		g.setAgent(agentID)
		tracker.SetProbe("protection", g.probe)
	}

	sender := shipper.NewHTTPSender(client, cfg.Server.URL, filepath.Join(cfg.StateDir, "quarantine"), log)
	sender.AttachStatus(tracker)

	statusCtx, stopStatus := context.WithCancel(context.Background())
	statusDone := make(chan struct{})
	go func() {
		tracker.Run(statusCtx, cfg.StateDir, 5*time.Second)
		close(statusDone)
	}()
	defer func() {
		stopStatus()
		<-statusDone
	}()

	bgCtx, stopBg := context.WithCancel(ctx)
	defer stopBg()

	// Bufor dyskowy: paczki, których nie udało się wysłać od razu, czekają na
	// dysku zamiast w dzienniku Windows (który przy długiej przerwie nadpisuje
	// niewysłane zdarzenia). Limit i zachowanie po zapełnieniu – z konfiguracji.
	buf, err := spool.Open(filepath.Join(cfg.StateDir, "buffer"), sender, log)
	if err != nil {
		return fmt.Errorf("bufor dyskowy: %w", err)
	}
	buf.FreeSpace = spool.DiskFree
	if st := buf.Stats(); st.Batches > 0 {
		log.Info("bufor dyskowy zawiera paczki z poprzedniego uruchomienia – dosyłam", "batches", st.Batches, "bytes", st.Bytes)
	}
	go buf.Run(bgCtx)
	tracker.SetProbe("buffer", func(s *status.Status) {
		b := buf.Stats()
		s.Buffer = &status.BufferStatus{Batches: b.Batches, Bytes: b.Bytes, MaxBytes: b.MaxBytes, OnFull: b.OnFull,
			OldestAt: b.OldestAt, Spooled: b.Spooled, Dropped: b.Dropped, Full: b.Full, Disabled: b.Disabled,
			LastError: b.LastError, LastErrorTime: b.LastErrorTime}
	})

	// Zegar i Sysmon (co 5 min): usługa czasu Windows, stan Sysmona; odchylenie
	// zegara względem serwera mierzy heartbeat.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			tracker.SetTimeService(timesync.ServiceState())
			tracker.SetSysmon(sysmon.Check())
			select {
			case <-bgCtx.Done():
				return
			case <-t.C:
			}
		}
	}()

	// Heartbeat dla panelu (Huginn): stan agenta co minutę. Przy zatrzymaniu
	// usługi – ostatni heartbeat z powodem (zatrzymanie bez tokenu panel widzi
	// od razu, nie dopiero po utracie łączności).
	if hbURL, err := heartbeat.URLFromIngest(cfg.Server.URL); err == nil {
		hb := &heartbeat.Sender{Client: client, URL: hbURL, AgentID: agentID, Version: version, Started: time.Now(),
			Status: func() any { return tracker.Snapshot() }, Clock: tracker.SetClock, Log: log}
		go hb.Run(bgCtx)
		defer func() {
			if ctx.Err() == nil || g == nil || g.stoppingReason() == "" {
				return // przeładowanie, błąd albo tryb konsoli
			}
			tracker.SetStopping(g.stoppingReason())
			fctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := hb.Send(fctx); err != nil {
				log.Warn("ostatni heartbeat nieudany", "err", err)
			}
		}()
	}

	// Bifröst: odnowienie certyfikatu przed wygaśnięciem (bez restartu agenta).
	panelURL := cfg.Server.PanelURL
	if panelURL == "" {
		panelURL, _ = enrollment.PanelURL(cfg.Server.URL)
	}
	if panelURL != "" {
		renewer := &enrollment.Renewer{Client: client, PanelURL: panelURL, CertFile: cfg.Server.CertFile, KeyFile: cfg.Server.KeyFile,
			Holder: certs, Log: log, Warn: tracker.Warn}
		go renewer.Run(bgCtx)
	}

	// Konfiguracja z panelu (grupa agentów): kanały i limity. Ostatnia znana
	// jest zapisana lokalnie; zmiana przeładowuje odczyt bez restartu usługi.
	current, err := managed.Load(cfg.StateDir)
	if err != nil {
		log.Warn("zapisana konfiguracja z panelu jest nieczytelna – używam agent.yaml", "err", err)
		current = nil
	}
	if g != nil {
		g.setConfig(current)
		go g.run(bgCtx)
	}
	reload := make(chan *contract.AgentConfig, 1)
	if panelURL != "" {
		// SIEM_CONFIG_POLL_SECONDS: częstsze sprawdzanie konfiguracji (diagnostyka, testy).
		pollEvery := 5 * time.Minute
		if s, err := strconv.Atoi(os.Getenv("SIEM_CONFIG_POLL_SECONDS")); err == nil && s >= 5 {
			pollEvery = time.Duration(s) * time.Second
		}
		poller := &managed.Poller{Client: client, PanelURL: panelURL, StateDir: cfg.StateDir, Log: log,
			Every: pollEvery,
			OnChange: func(c *contract.AgentConfig) {
				select {
				case <-reload: // starsza oczekująca zmiana – zastępujemy ją nowszą
				default:
				}
				reload <- c
			}}
		go poller.Run(bgCtx, current)
	}

	log.Info("agent uruchomiony", "version", version, "eventlog", true)
	defer func() {
		s := sender.Stats
		log.Info("agent zatrzymany", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load(),
			"retries", s.Retries.Load(), "events_quarantined", s.EventsQuarantined.Load(), "eventlog", true)
	}()

	for {
		eff, err := managed.Apply(cfg, current)
		if err != nil {
			log.Error("nie można zastosować konfiguracji z panelu – używam agent.yaml", "err", err, "eventlog", true)
			tracker.Warn("konfiguracja z panelu odrzucona: " + err.Error())
			eff, current = cfg, nil
		}
		cs := status.ConfigStatus{Source: "local", AppliedAt: time.Now()}
		if current != nil {
			cs = status.ConfigStatus{Source: "panel", Group: current.Group, Version: current.Version, AppliedAt: time.Now()}
		}
		tracker.SetConfig(cs)

		// Limity: Job Object aktualizowany w miejscu (bez nakładania kolejnego).
		if err := lim.Update(eff.Limits.Resource()); err != nil {
			log.Error("zmiana limitów zasobów nieudana", "err", err)
		}
		runtime.GOMAXPROCS(eff.Limits.MaxProcs)
		sender.Bandwidth = nil
		if kbps := eff.Limits.MaxSendKBps; kbps > 0 {
			sender.Bandwidth = throttle.New(float64(kbps)*1024, float64(kbps)*1024)
		}
		buf.Configure(eff.Buffer.MaxBytes(), eff.Buffer.OnFull, int64(eff.Buffer.MinFreeMB)<<20)
		tracker.SetLimits(limitMap(eff.Limits))
		tracker.ResetChannels()
		log.Info("konfiguracja kanałów i limitów", append([]any{"source", cs.Source, "group", cs.Group, "version", cs.Version,
			"channels", len(eff.Channels), "buffer_max_mb", eff.Buffer.MBValue(), "buffer_on_full", eff.Buffer.OnFull},
			limitAttrs(eff.Limits)...)...)

		next, err := runPipeline(ctx, eff, agentID, buf, store, tracker, log, reload)
		if ctx.Err() != nil {
			return nil
		}
		if next == nil {
			return err // agent zakończył się sam (błąd) – usługa uruchomi się ponownie
		}
		log.Info("nowa konfiguracja z panelu – przeładowuję odczyt", "group", next.Group, "version", next.Version, "eventlog", true)
		current = next
		if g != nil {
			g.setConfig(current)
		}
	}
}

// runPipeline uruchamia odczyt kanałów i wysyłkę dla danej konfiguracji.
// Kończy się przy anulowaniu ctx albo nadejściu nowej konfiguracji (wtedy
// zwraca ją – pozycje odczytu są już zapisane, odczyt wznowi się od nich).
func runPipeline(ctx context.Context, cfg *config.Config, agentID string, sender core.Sender, store *state.Store,
	tracker *status.Tracker, log *slog.Logger, reload <-chan *contract.AgentConfig) (*contract.AgentConfig, error) {
	var sources []source.Source
	var watched []logwatch.Channel
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
		reader := winevt.NewReader(ch.Name, q, cfg.StartAt, log)
		reader.OnGap = tracker.Warn
		sources = append(sources, reader)
		watched = append(watched, logwatch.Channel{
			Name:        ch.Name,
			LastDrained: reader.LastDrained,
			LastRead:    lastRead(tracker, ch.Name),
		})
	}

	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     cfg.Batch.MaxEvents,
		MaxBytes:      cfg.Batch.MaxBytes,
		MaxEventBytes: cfg.Batch.MaxEventBytes,
		FlushInterval: cfg.Batch.FlushInterval,
		FlushMaxWait:  cfg.Batch.FlushMaxWait, FlushMinEvents: cfg.Batch.FlushMinEvents,
		Filters:       filters,
		RetryDelay:    retryDelay,
		MaxEPS:        cfg.Limits.MaxEPS,
		Status:        tracker,
		ClassifyError: classifyError,
	}, sources, sender, store, log)

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	// Ostrzeżenie, zanim dziennik Windows nadpisze niewysłane zdarzenia (K3).
	watcher := &logwatch.Watcher{Info: winevt.LogInfo, Channels: watched, Log: log, Warn: tracker.Warn,
		Interval: time.Minute, WarnAt: 0.5, AlarmAt: 0.8}
	go watcher.Run(runCtx)

	// Nowa konfiguracja przerywa odczyt; przekazujemy ją kanałem (bez wspólnej zmiennej).
	nextCh := make(chan *contract.AgentConfig, 1)
	go func() {
		select {
		case c := <-reload:
			nextCh <- c
			stop()
		case <-runCtx.Done():
		}
	}()
	err := agent.Run(runCtx)
	stop()
	select {
	case c := <-nextCh:
		return c, nil
	default:
		return nil, err
	}
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

// lastRead zwraca numer ostatniego przeczytanego rekordu kanału (ze statusu).
func lastRead(t *status.Tracker, channel string) func() (uint64, bool) {
	return func() (uint64, bool) {
		for _, c := range t.Snapshot().Channels {
			if c.Name == channel && c.LastRecordID > 0 {
				return c.LastRecordID, true
			}
		}
		return 0, false
	}
}
