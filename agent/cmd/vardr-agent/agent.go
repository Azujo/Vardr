// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows || linux

package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"siem/agent/internal/config"
	"siem/agent/internal/core"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/limits"
	"siem/agent/internal/managed"
	"siem/agent/internal/setup"
	"siem/agent/internal/shipper"
	"siem/agent/internal/source"
	"siem/agent/internal/spool"
	"siem/agent/internal/state"
	"siem/agent/internal/status"
	"siem/agent/internal/update"
	"siem/internal/contract"
	"siem/internal/lang"
	"siem/internal/throttle"
)

// Wspólny rdzeń agenta Windows i Linux: bufor dyskowy, wysyłka, heartbeat,
// odnowienie certyfikatu i konfiguracja z panelu. Różnice systemów (źródła,
// usługa, uprawnienia plików, ochrona) – w platform_<system>.go.

// agentGuard: ochrona agenta w procesie usługi (guardian w Windows).
type agentGuard interface {
	setAgent(id string)
	setConfig(c *contract.AgentConfig)
	probe(s *status.Status)
	stoppingReason() string
	run(ctx context.Context)
}

// pipelineSources: źródła odczytu danej konfiguracji.
type pipelineSources struct {
	sources []source.Source
	filters map[string]map[uint32]bool // kanał → dozwolone Event ID (filtr po stronie agenta)
	watch   func(ctx context.Context)  // dodatkowy nadzór na czas odczytu (może być nil)
	// rescan czeka na nowe źródła (np. nowy plik pasujący do wzorca) – true:
	// odczyt rusza od nowa z nową listą (może być nil).
	rescan func(ctx context.Context) bool
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
	privileged := isPrivileged()
	if privileged {
		if why := programWarning(); why != "" {
			log.Error("the agent program file can be replaced by an ordinary user – privilege escalation risk", "why", why)
			tracker.Warn(lang.L("plik programu agenta może zostać podmieniony przez zwykłego użytkownika – ryzyko eskalacji uprawnień: ",
				"the agent program file can be replaced by an ordinary user – privilege escalation risk: ") + why)
		}
	}

	// Stan: plik w state_dir + kopia poza nim (Windows: rejestr – znacznik
	// wcześniejszego działania).
	store := state.NewStore(cfg.StateDir)
	if backup, where := stateBackup(privileged, cfg.StateDir); backup != nil {
		store.Backup = backup
		log.Info("agent state backup", "location", where)
	}
	store.OnRecreate = func(dir string) error {
		log.Error("the agent state directory was deleted – recreated it (possible tampering)", "dir", dir)
		tracker.Warn(lang.L("katalog stanu agenta został usunięty – utworzono go ponownie (możliwa manipulacja)",
			"the agent state directory was deleted – recreated it (possible tampering)"))
		if privileged {
			return restrictDir(dir)
		}
		return nil
	}
	tracker.AddProbe(func(s *status.Status) {
		s.Warnings = append(s.Warnings, warnings...)
		s.Process.CPUTime = processCPUTime()
	})

	g := currentGuard()
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
	// dysku zamiast w dzienniku systemu (który przy długiej przerwie nadpisuje
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

	// Stan systemu co 5 min (Windows: usługa czasu, Sysmon); odchylenie zegara
	// względem serwera mierzy heartbeat.
	go systemProbes(bgCtx, tracker)

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

	// Automatyczna aktualizacja (grupa z włączoną opcją): tylko usługa –
	// Windows: instalator MSI zatrzymuje ją i uruchamia nową wersję; Linux:
	// apply-update nowego programu (update_linux.go).
	var upd *update.Updater
	if autoUpdate && panelURL != "" && g != nil {
		upd = &update.Updater{Client: client, PanelURL: panelURL, Dir: cfg.StateDir, Version: version, Log: log,
			Warn: tracker.Warn, Report: tracker.SetUpdate, MaxDelay: 30 * time.Minute}
		platformUpdater(upd)
		// SIEM_UPDATE_DELAY_SECONDS: krótsze losowe opóźnienie (testy, laboratorium).
		if s, err := strconv.Atoi(os.Getenv("SIEM_UPDATE_DELAY_SECONDS")); err == nil && s >= 0 {
			upd.MaxDelay = time.Duration(s) * time.Second
		}
		go upd.Run(bgCtx)
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
		if upd != nil {
			upd.Offer(updateOffer(current))
		}

		// Limity zmieniane w miejscu (Windows: ten sam Job Object).
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

// runPipeline uruchamia odczyt źródeł i wysyłkę dla danej konfiguracji.
// Kończy się przy anulowaniu ctx albo nadejściu nowej konfiguracji (wtedy
// zwraca ją – pozycje odczytu są już zapisane, odczyt wznowi się od nich).
func runPipeline(ctx context.Context, cfg *config.Config, agentID string, sender core.Sender, store *state.Store,
	tracker *status.Tracker, log *slog.Logger, reload <-chan *contract.AgentConfig) (*contract.AgentConfig, error) {
	for {
		next, again, err := runSources(ctx, cfg, agentID, sender, store, tracker, log, reload)
		if !again || ctx.Err() != nil {
			return next, err
		}
		log.Info("new sources found – restarting the readers")
	}
}

// runSources: jeden przebieg odczytu; again – źródła się zmieniły (rescan).
func runSources(ctx context.Context, cfg *config.Config, agentID string, sender core.Sender, store *state.Store,
	tracker *status.Tracker, log *slog.Logger, reload <-chan *contract.AgentConfig) (next *contract.AgentConfig, again bool, err error) {
	src := platformSources(cfg, tracker, log)

	agent := core.New(core.Options{
		AgentID:       agentID,
		MaxEvents:     cfg.Batch.MaxEvents,
		MaxBytes:      cfg.Batch.MaxBytes,
		MaxEventBytes: cfg.Batch.MaxEventBytes,
		FlushInterval: cfg.Batch.FlushInterval,
		FlushMaxWait:  cfg.Batch.FlushMaxWait, FlushMinEvents: cfg.Batch.FlushMinEvents,
		Filters:       src.filters,
		RetryDelay:    retryDelay,
		MaxEPS:        cfg.Limits.MaxEPS,
		Status:        tracker,
		ClassifyError: classifyError,
	}, src.sources, sender, store, log)

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	if src.watch != nil {
		go src.watch(runCtx)
	}
	rescanned := make(chan struct{}, 1)
	if src.rescan != nil {
		go func() {
			if src.rescan(runCtx) {
				rescanned <- struct{}{}
				stop()
			}
		}()
	}

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
	err = agent.Run(runCtx)
	stop()
	select {
	case c := <-nextCh:
		return c, false, nil
	default:
	}
	select {
	case <-rescanned:
		return nil, true, nil
	default:
		return nil, false, err
	}
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

type enrollOptions struct {
	server, token, ca, panel, dir, profile string
}

// enrollOnly rejestruje agenta tokenem i przygotowuje samodzielny katalog
// (certyfikaty + agent.yaml) bez instalowania usługi – do testów, do
// uruchomienia w konsoli (vardr-agent run) albo do własnych skryptów.
// Nie wymaga uprawnień administratora.
func enrollOnly(o enrollOptions) error {
	if o.server == "" || o.token == "" || o.dir == "" {
		return errors.New(lang.L("użycie: vardr-agent enroll -server <adres> -token <token> -dir <katalog> [-ca ca.crt] [-panel URL] [-profile …]", "usage: vardr-agent enroll -server <address> -token <token> -dir <directory> [-ca ca.crt] [-panel URL] [-profile …]"))
	}
	serverURL, err := setup.ServerURL(o.server)
	if err != nil {
		return err
	}
	if o.panel == "" {
		if o.panel, err = enrollment.PanelURL(serverURL); err != nil {
			return err
		}
	}
	if o.ca == "" {
		exe, _ := os.Executable()
		o.ca = filepath.Join(filepath.Dir(exe), "ca.crt")
	}
	caPEM, err := os.ReadFile(o.ca)
	if err != nil {
		return fmt.Errorf(lang.L("plik CA (-ca): %w", "CA file (-ca): %w"), err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New(lang.L("niepoprawny plik CA", "invalid CA file"))
	}
	if _, err := os.Stat(filepath.Join(o.dir, "certs", "agent.key")); err == nil {
		return fmt.Errorf(lang.L("%s zawiera już klucz agenta – wskaż pusty katalog", "%s already contains an agent key – choose an empty directory"), o.dir)
	}

	host, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, keyPEM, err := enrollment.Register(ctx, o.panel, roots, o.token, enrollment.Info{Hostname: host, OS: heartbeat.OSVersion(), Version: version})
	if err != nil {
		return err
	}
	certDir := filepath.Join(o.dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), caPEM, 0o644); err != nil {
		return err
	}
	if err := enrollment.WritePair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), []byte(res.Certificate), keyPEM); err != nil {
		return err
	}
	profile := o.profile
	if profile == "" {
		profile = res.Profile
	}
	gen := setup.GenerateConfig
	if runtime.GOOS == "linux" {
		gen = setup.GenerateLinuxConfig
	}
	cfg, err := gen(setup.Options{ServerURL: serverURL, Profile: profile})
	if err != nil {
		return err
	}
	cfg += "\n# Katalog stanu obok konfiguracji (rejestracja poleceniem vardr-agent enroll).\nstate_dir: state\n"
	cfgPath := filepath.Join(o.dir, "agent.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return err
	}
	fmt.Printf(lang.L("Zarejestrowano agenta %s (profil %s, certyfikat ważny do %s).\n", "Agent %s enrolled (profile %s, certificate valid until %s).\n"), res.AgentID, profile, res.NotAfter.Local().Format("2006-01-02"))
	fmt.Printf("Konfiguracja: %s\nUruchomienie w konsoli: vardr-agent -config %s run\n", cfgPath, cfgPath)
	return nil
}

// setServer zmienia adres serwera w konfiguracji, sprawdza połączenie
// i restartuje usługę.
func setServer(cfgPath, input string) error {
	if err := requireAdmin(lang.L("Zmiana adresu serwera", "Changing the server address")); err != nil {
		return err
	}
	serverURL, err := setup.ServerURL(input)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	updated, err := setup.SetServerURL(data, serverURL)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath+".tmp", updated, 0o600); err != nil {
		return err
	}
	if _, err := config.Load(cfgPath + ".tmp"); err != nil {
		_ = os.Remove(cfgPath + ".tmp")
		return fmt.Errorf(lang.L("konfiguracja po zmianie byłaby niepoprawna: %w", "the configuration would be invalid after the change: %w"), err)
	}
	if err := os.Rename(cfgPath+".tmp", cfgPath); err != nil {
		return err
	}
	fmt.Println(lang.L("Nowy adres serwera:", "New server address:"), serverURL)
	if err := testConnection(cfgPath); err != nil {
		fmt.Println(lang.L("UWAGA:", "WARNING:"), err)
	}
	if serviceRunning() {
		return restartService()
	}
	return nil
}

// testConnection sprawdza połączenie z serwerem z bieżącej konfiguracji.
func testConnection(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return errors.New(lang.L("brak dostępu do konfiguracji – uruchom jako administrator", "no access to the configuration – run as administrator"))
		}
		return err
	}
	client, agentID, err := shipper.NewTLSClient(cfg.Server.CAFile, cfg.Server.CertFile, cfg.Server.KeyFile, 10*time.Second)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := shipper.CheckServer(ctx, client, cfg.Server.URL); err != nil {
		return fmt.Errorf(lang.L("połączenie z %s nieudane: %w", "connection to %s failed: %w"), cfg.Server.URL, err)
	}
	fmt.Printf(lang.L("Połączenie z %s: OK (agent %s, %s)\n", "Connection to %s: OK (agent %s, %s)\n"), cfg.Server.URL, agentID, time.Since(start).Round(time.Millisecond))
	return nil
}

func prompt(question string) (string, error) {
	fmt.Print(question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New(lang.L("nie podano adresu serwera (użyj: vardr-agent install -server <adres>)", "no server address given (use: vardr-agent install -server <address>)"))
	}
	return strings.TrimSpace(line), nil
}
