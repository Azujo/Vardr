// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

// Command vardr-agent to agent Windows zbierający zdarzenia z Event Log
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
	"siem/internal/lang"
	"siem/internal/throttle"
)

const version = "0.9.0"

func usage() {
	if lang.Local() == "en" {
		fmt.Fprintf(os.Stderr, usageEn, version, installCfg)
		return
	}
	fmt.Fprintf(os.Stderr, `vardr-agent %s – agent SIEM dla Windows

Instalacja (PowerShell lub cmd jako administrator, w folderze z vardr-agent.exe,
ca.crt, agent.crt i agent.key):
  vardr-agent install [-server adres] [-token token] [-profile workstation|server|dc] [-start-at now|oldest] [-no-start]
      -server   adres serwera, np. 192.168.88.98 lub siem.firma.local:8443 (bez -server: pytanie)
      -profile  zestaw zbieranych zdarzeń (domyślnie workstation)
      -token    token rejestracyjny z panelu (Bifröst) – agent sam wygeneruje klucz i pobierze
                certyfikat; w paczce z panelu token jest w pliku token.txt
      -ca, -cert, -key   inne położenie certyfikatów

Sterowanie (po instalacji polecenie działa z każdego miejsca):
  vardr-agent status                 stan usługi, połączenia, kanałów, limitów i ochrony
  vardr-agent start | restart
  vardr-agent stop [-token T]        zatrzymanie (agent chroniony: token z panelu)
  vardr-agent test                   sprawdzenie połączenia z serwerem
  vardr-agent set-server <adres>     zmiana adresu serwera (restartuje agenta)
  vardr-agent upgrade [-token T]     aktualizacja programu (uruchom z folderu nowej wersji)
  vardr-agent uninstall [-token T] [-purge]
                                    odinstalowanie (-purge: także dane i certyfikaty)

Ochrona: agent w grupie z włączoną ochroną (domyślnie) ma usługę, której
administrator nie zatrzyma ani nie usunie bez jednorazowego tokenu z panelu
(Huginn → agent → Token deinstalacji). Próby bez tokenu panel zgłasza jako alert.

Diagnostyka:
  vardr-agent check                  walidacja konfiguracji, certyfikatów i uprawnień
  vardr-agent run                    uruchomienie w konsoli zamiast usługi (Ctrl+C kończy)
  vardr-agent enroll -server <adres> -token <token> -dir <katalog>
                                    rejestracja bez instalacji usługi (test, konsola)
  vardr-agent version

Opcja -config <plik> (przed lub po poleceniu) wskazuje inną konfigurację.
Domyślnie: %s (po instalacji) lub agent.yaml obok programu.
`, version, installCfg)
}

const usageEn = `vardr-agent %s – SIEM agent for Windows

Installation (PowerShell or cmd as administrator, in the folder with vardr-agent.exe,
ca.crt, agent.crt and agent.key):
  vardr-agent install [-server address] [-token token] [-profile workstation|server|dc] [-start-at now|oldest] [-no-start]
      -server   server address, e.g. 192.168.88.98 or siem.company.local:8443 (without -server: prompt)
      -profile  set of collected events (default workstation)
      -token    enrollment token from the panel (Bifröst) – the agent generates its key and fetches
                a certificate; in a package from the panel the token is in token.txt
      -ca, -cert, -key   other certificate locations

Control (after installation the command works from anywhere):
  vardr-agent status                 state of the service, connection, channels, limits and protection
  vardr-agent start | restart
  vardr-agent stop [-token T]        stop (protected agent: token from the panel)
  vardr-agent test                   check the connection to the server
  vardr-agent set-server <address>   change the server address (restarts the agent)
  vardr-agent upgrade [-token T]     upgrade the program (run from the folder of the new version)
  vardr-agent uninstall [-token T] [-purge]
                                    uninstall (-purge: also data and certificates)

Protection: an agent in a group with protection enabled (default) has a service that
an administrator cannot stop or remove without a one-time token from the panel
(Huginn → agent → Uninstall token). Attempts without a token are reported by the panel as an alert.

Diagnostics:
  vardr-agent check                  validate the configuration, certificates and permissions
  vardr-agent run                    run in the console instead of as a service (Ctrl+C stops)
  vardr-agent enroll -server <address> -token <token> -dir <directory>
                                    enroll without installing the service (test, console)
  vardr-agent version

The -config <file> option (before or after the command) points to another configuration.
Default: %s (after installation) or agent.yaml next to the program.

Messages follow the Windows language (VARDR_LANG=pl|en overrides it).
`

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
	global := flag.NewFlagSet("vardr-agent", flag.ExitOnError)
	global.Usage = usage
	cfgFlag := global.String("config", "", lang.L("plik konfiguracji", "configuration file"))
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
	cfgPath := cf.String("config", *cfgFlag, lang.L("plik konfiguracji", "configuration file"))
	var opts installOptions
	var eo enrollOptions
	purge := new(bool)
	var token, upgradeCode string
	switch cmd {
	case "stop", "upgrade":
		cf.StringVar(&token, "token", "", lang.L("token deinstalacji z panelu (agent chroniony)", "uninstall token from the panel (protected agent)"))
	case "msi-uninstall":
		cf.StringVar(&token, "token", "", lang.L("token deinstalacji (właściwość UNINSTALL_TOKEN instalatora MSI)", "uninstall token (UNINSTALL_TOKEN property of the MSI installer)"))
		cf.StringVar(&upgradeCode, "upgrade", "", lang.L("kod produktu aktualizującego (UPGRADINGPRODUCTCODE – aktualizacja, nie deinstalacja)",
			"upgrading product code (UPGRADINGPRODUCTCODE – an upgrade, not an uninstall)"))
	case "install":
		cf.StringVar(&opts.server, "server", "", lang.L("adres serwera", "server address"))
		cf.StringVar(&opts.profile, "profile", "", lang.L("profil zdarzeń (domyślnie z tokenu albo workstation)", "event profile (default from the token or workstation)"))
		cf.StringVar(&opts.token, "token", "", lang.L("token rejestracyjny z panelu (zamiast certyfikatu w paczce)", "enrollment token from the panel (instead of a certificate in the package)"))
		cf.StringVar(&opts.panel, "panel", "", lang.L("adres panelu do rejestracji (domyślnie https://<serwer>:8444)", "panel address for enrollment (default https://<server>:8444)"))
		cf.StringVar(&opts.startAt, "start-at", "now", "now | oldest")
		cf.StringVar(&opts.ca, "ca", "", lang.L("plik CA", "CA file"))
		cf.StringVar(&opts.cert, "cert", "", lang.L("certyfikat agenta", "agent certificate"))
		cf.StringVar(&opts.key, "key", "", lang.L("klucz agenta", "agent key"))
		cf.BoolVar(&opts.noStart, "no-start", false, lang.L("nie uruchamiaj usługi po instalacji", "do not start the service after installation"))
	case "msi-install":
		cf.StringVar(&opts.server, "server", "", lang.L("adres serwera (właściwość SERVER instalatora MSI)", "server address (SERVER property of the MSI installer)"))
		cf.StringVar(&opts.token, "token", "", lang.L("token rejestracyjny (właściwość TOKEN instalatora MSI)", "enrollment token (TOKEN property of the MSI installer)"))
	case "uninstall":
		purge = cf.Bool("purge", false, lang.L("usuń także dane, konfigurację i certyfikaty", "also remove data, configuration and certificates"))
		cf.StringVar(&token, "token", "", lang.L("token deinstalacji z panelu (agent chroniony)", "uninstall token from the panel (protected agent)"))
	case "enroll":
		cf.StringVar(&eo.server, "server", "", lang.L("adres serwera", "server address"))
		cf.StringVar(&eo.token, "token", "", lang.L("token rejestracyjny z panelu", "enrollment token from the panel"))
		cf.StringVar(&eo.ca, "ca", "", lang.L("plik głównego CA (domyślnie ca.crt obok programu)", "root CA file (default ca.crt next to the program)"))
		cf.StringVar(&eo.panel, "panel", "", lang.L("adres panelu (domyślnie https://<serwer>:8444)", "panel address (default https://<server>:8444)"))
		cf.StringVar(&eo.dir, "dir", "", lang.L("katalog na certyfikaty i agent.yaml", "directory for certificates and agent.yaml"))
		cf.StringVar(&eo.profile, "profile", "", lang.L("profil zdarzeń (domyślnie z tokenu)", "event profile (default from the token)"))
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
			err = errors.New(lang.L("użycie: vardr-agent set-server <adres>, np. vardr-agent set-server 192.168.88.98",
				"usage: vardr-agent set-server <address>, e.g. vardr-agent set-server 192.168.88.98"))
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
		fmt.Fprintf(os.Stderr, lang.L("nieznane polecenie %q\n\n", "unknown command %q\n\n"), cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, lang.L("błąd:", "error:"), errText(err))
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
	fmt.Printf(lang.L("Konfiguracja poprawna.\n  agent_id:  %s\n  serwer:    %s\n  state_dir: %s\n",
		"Configuration valid.\n  agent_id:  %s\n  server:    %s\n  state_dir: %s\n"), agentID, cfg.Server.URL, cfg.StateDir)
	fmt.Printf(lang.L("  limity:    %s\n", "  limits:    %s\n"), formatKV(limitAttrs(cfg.Limits)))
	fmt.Printf(lang.L("  klucz:     %s – %s\n", "  key:       %s – %s\n"), cfg.Server.KeyFile, protection(cfg.Server.KeyFile))
	exe, _ := os.Executable()
	if ok, why := secure.ServiceBinarySafe(exe); ok {
		fmt.Printf(lang.L("  program:   %s – chroniony przed zapisem przez zwykłych użytkowników\n", "  program:   %s – protected against writes by ordinary users\n"), exe)
	} else {
		fmt.Printf(lang.L("  program:   UWAGA – %s\n             (usługa uruchomiona z tego miejsca pozwoliłaby podmienić program działający jako SYSTEM)\n",
			"  program:   WARNING – %s\n             (a service run from this location would allow replacing a program running as SYSTEM)\n"), why)
	}
	if _, err := os.Stat(cfg.StateDir); err == nil {
		fmt.Printf(lang.L("  stan:      %s – %s\n", "  state:     %s – %s\n"), cfg.StateDir, protection(cfg.StateDir))
	}
	for _, ch := range cfg.Channels {
		q, agentSide := winevt.BuildQuery(ch.EventIDs)
		mode := lang.L("filtr w zapytaniu XPath", "filter in the XPath query")
		if agentSide {
			mode = lang.L("filtr po stronie agenta (lista za długa dla XPath)", "agent-side filter (list too long for XPath)")
		}
		fmt.Printf(lang.L("  kanał %-45s %s\n    %s\n", "  channel %-43s %s\n    %s\n"), ch.Name, mode, q)
	}
	return nil
}

func protection(path string) string {
	ok, why, err := secure.IsRestricted(path)
	switch {
	case err != nil:
		return lang.L("nie można sprawdzić uprawnień: ", "cannot check permissions: ") + errText(err)
	case ok:
		return lang.L("chroniony (tylko SYSTEM i Administratorzy)", "protected (SYSTEM and Administrators only)")
	default:
		return lang.L("UWAGA: ", "WARNING: ") + why
	}
}

// protectFiles zawęża uprawnienia katalogu stanu i klucza prywatnego.
// Zwraca ostrzeżenia do pokazania w statusie.
func protectFiles(cfg *config.Config, log *slog.Logger) []string {
	if !secure.IsPrivileged() {
		w := lang.L("agent działa bez uprawnień administratora – uprawnienia katalogu stanu i klucza nie zostały zawężone",
			"the agent runs without administrator rights – permissions of the state directory and the key were not restricted")
		log.Warn("the agent runs without administrator rights – permissions of the state directory and the key were not restricted")
		return []string{w}
	}
	var warns []string
	if err := secure.RestrictDir(cfg.StateDir); err != nil {
		warns = append(warns, errText(err))
		log.Error("securing agent files failed", "err", err)
	}
	if err := secure.RestrictFile(cfg.Server.KeyFile); err != nil {
		warns = append(warns, errText(err))
		log.Error("securing agent files failed", "err", err)
	}
	return warns
}

// runAgent buduje komponenty z konfiguracji i uruchamia rdzeń agenta.
func runAgent(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return lang.Errorf("katalog stanu: %w", "state directory: %w", err)
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
		return lang.Errorf("limity zasobów: %w", "resource limits: %w", err)
	}
	defer lim.Close()
	log.Info("resource limits active", limitAttrs(cfg.Limits)...)

	tracker := status.NewTracker(version, agentID, cfg.Server.URL, limitMap(cfg.Limits))
	privileged := secure.IsPrivileged()
	if exe, err := os.Executable(); err == nil && privileged {
		if ok, why := secure.ServiceBinarySafe(exe); !ok {
			log.Error("the agent program file can be replaced by an ordinary user – privilege escalation risk", "why", why)
			tracker.Warn(lang.L("plik programu agenta może zostać podmieniony przez zwykłego użytkownika – ryzyko eskalacji uprawnień: ",
				"the agent program file can be replaced by an ordinary user – privilege escalation risk: ") + why)
		}
	}

	// Stan: plik w state_dir + kopia w rejestrze (znacznik wcześniejszego działania).
	backup := state.NewRegistryBackup(privileged, cfg.StateDir)
	store := state.NewStore(cfg.StateDir)
	store.Backup = backup
	store.OnRecreate = func(dir string) error {
		log.Error("the agent state directory was deleted – recreated it (possible tampering)", "dir", dir)
		tracker.Warn(lang.L("katalog stanu agenta został usunięty – utworzono go ponownie (możliwa manipulacja)",
			"the agent state directory was deleted – recreated it (possible tampering)"))
		if privileged {
			return secure.RestrictDir(dir)
		}
		return nil
	}
	log.Info("agent state backup", "location", backup.Location())
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
		return lang.Errorf("bufor dyskowy: %w", "disk buffer: %w", err)
	}
	buf.FreeSpace = spool.DiskFree
	if st := buf.Stats(); st.Batches > 0 {
		log.Info("the disk buffer holds batches from the previous run – sending them", "batches", st.Batches, "bytes", st.Bytes)
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
				log.Warn("last heartbeat failed", "err", err)
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
		log.Warn("the saved configuration from the panel is unreadable – using agent.yaml", "err", err)
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

	log.Info("agent started", "version", version, "eventlog", true)
	defer func() {
		s := sender.Stats
		log.Info("agent stopped", "batches_accepted", s.BatchesAccepted.Load(), "events_accepted", s.EventsAccepted.Load(),
			"retries", s.Retries.Load(), "events_quarantined", s.EventsQuarantined.Load(), "eventlog", true)
	}()

	for {
		eff, err := managed.Apply(cfg, current)
		if err != nil {
			log.Error("cannot apply the configuration from the panel – using agent.yaml", "err", err, "eventlog", true)
			tracker.Warn(lang.L("konfiguracja z panelu odrzucona: ", "configuration from the panel rejected: ") + errText(err))
			eff, current = cfg, nil
		}
		cs := status.ConfigStatus{Source: "local", AppliedAt: time.Now()}
		if current != nil {
			cs = status.ConfigStatus{Source: "panel", Group: current.Group, Version: current.Version, AppliedAt: time.Now()}
		}
		tracker.SetConfig(cs)

		// Limity: Job Object aktualizowany w miejscu (bez nakładania kolejnego).
		if err := lim.Update(eff.Limits.Resource()); err != nil {
			log.Error("changing resource limits failed", "err", err)
		}
		runtime.GOMAXPROCS(eff.Limits.MaxProcs)
		sender.Bandwidth = nil
		if kbps := eff.Limits.MaxSendKBps; kbps > 0 {
			sender.Bandwidth = throttle.New(float64(kbps)*1024, float64(kbps)*1024)
		}
		buf.Configure(eff.Buffer.MaxBytes(), eff.Buffer.OnFull, int64(eff.Buffer.MinFreeMB)<<20)
		tracker.SetLimits(limitMap(eff.Limits))
		tracker.ResetChannels()
		log.Info("channel and limit configuration", append([]any{"source", cs.Source, "group", cs.Group, "version", cs.Version,
			"channels", len(eff.Channels), "buffer_max_mb", eff.Buffer.MBValue(), "buffer_on_full", eff.Buffer.OnFull},
			limitAttrs(eff.Limits)...)...)

		next, err := runPipeline(ctx, eff, agentID, buf, store, tracker, log, reload)
		if ctx.Err() != nil {
			return nil
		}
		if next == nil {
			return err // agent zakończył się sam (błąd) – usługa uruchomi się ponownie
		}
		log.Info("new configuration from the panel – reloading the readers", "group", next.Group, "version", next.Version, "eventlog", true)
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
			log.Warn("Event ID list too long for XPath – agent-side filter", "channel", ch.Name, "ids", len(ch.EventIDs))
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
		fmt.Println(lang.L("Usługa SiemAgent: nie jest zainstalowana", "SiemAgent service: not installed"))
	case err != nil:
		fmt.Printf(lang.L("Usługa SiemAgent: nie można sprawdzić (%v)\n", "SiemAgent service: cannot check (%v)\n"), err)
	default:
		fmt.Printf(lang.L("Usługa SiemAgent: %s", "SiemAgent service: %s"), stateName(st.State))
		if st.ProcessId != 0 {
			fmt.Printf(" (PID %d)", st.ProcessId)
		}
		fmt.Println()
	}

	cfg, err := config.Load(cfgPath)
	if errors.Is(err, fs.ErrPermission) {
		fmt.Println(lang.L("\nSzczegóły (połączenie, kanały, liczniki) są dostępne tylko dla administratora –",
			"\nDetails (connection, channels, counters) are available to administrators only –"))
		fmt.Println(lang.L("uruchom PowerShell lub cmd jako administrator.", "run PowerShell or cmd as administrator."))
		return nil
	}
	if err != nil {
		return err
	}
	p := filepath.Join(cfg.StateDir, status.FileName)
	s, err := status.Read(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf(lang.L("brak pliku statusu %s – agent jeszcze nie był uruchomiony z tą konfiguracją",
			"no status file %s – the agent has not run with this configuration yet"), p)
	case errors.Is(err, fs.ErrPermission):
		fmt.Println(lang.L("\nSzczegóły są dostępne tylko dla administratora – uruchom PowerShell lub cmd jako administrator.",
			"\nDetails are available to administrators only – run PowerShell or cmd as administrator."))
		return nil
	case err != nil:
		return err
	}
	fmt.Println()
	status.Render(os.Stdout, s, time.Now())
	return nil
}

// errText: opis błędu w języku systemu (lang.Error – także po angielsku).
func errText(err error) string {
	if lang.Local() == "en" {
		return lang.English(err)
	}
	return err.Error()
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
