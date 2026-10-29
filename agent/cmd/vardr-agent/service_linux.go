// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"siem/agent/internal/auditd"
	"siem/agent/internal/config"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/limits"
	"siem/agent/internal/logging"
	"siem/agent/internal/setup"
	"siem/agent/internal/shipper"
	"siem/internal/lang"
)

// Docelowe lokalizacje instalacji.
const (
	installExe = "/usr/local/sbin/vardr-agent"
	configDir  = "/etc/vardr-agent"
	installCfg = configDir + "/agent.yaml"
	dataDir    = "/var/lib/vardr-agent"
	unitName   = limits.Unit
	unitPath   = "/etc/systemd/system/" + unitName
)

// unitFile: usługa systemd. Restart po awarii; system plików tylko do odczytu
// poza konfiguracją (odnowienie certyfikatu), katalogiem stanu i katalogiem
// jednostek systemd (ochrona agenta: drop-in RefuseManualStop, przywracanie
// pliku usługi). Rozliczanie pamięci i I/O – limity z panelu (systemctl
// set-property; CPU rozliczane zawsze).
const unitFile = `[Unit]
Description=Vardr SIEM agent
Documentation=https://github.com/Azujo/Vardr/blob/master/docs/agent.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + installExe + ` -config ` + installCfg + ` service
Restart=always
RestartSec=10
TimeoutStopSec=30
KillMode=mixed
MemoryAccounting=yes
IOAccounting=yes
NoNewPrivileges=yes
ProtectSystem=full
ReadWritePaths=` + configDir + ` ` + dataDir + ` /etc/systemd/system
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0077

[Install]
WantedBy=multi-user.target
`

func requireAdmin(what string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf(lang.L("%s wymaga uprawnień roota – uruchom przez sudo", "%s requires root privileges – run it with sudo"), what)
	}
	return nil
}

// systemctl uruchamia polecenie systemd i zwraca jego wyjście.
func systemctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), text)
		}
		return text, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}

// unitActive: stan usługi (active, inactive, failed…; "" – nie zainstalowana).
func unitActive() string {
	if _, err := os.Stat(unitPath); err != nil {
		return ""
	}
	out, _ := systemctl("is-active", unitName)
	return out
}

var errNotInstalled = lang.Errorf("agent nie jest zainstalowany (brak usługi "+unitName+") – zainstaluj: sudo vardr-agent install",
	"the agent is not installed (no "+unitName+" service) – install it: sudo vardr-agent install")

func requireSystemd() error {
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return errors.New(lang.L("system nie działa pod systemd – usługi nie można zainstalować (uruchom agenta poleceniem run albo własnym skryptem)",
			"the system is not running systemd – the service cannot be installed (run the agent with the run command or your own script)"))
	}
	return nil
}

func startService() error {
	if unitActive() == "" {
		return errNotInstalled
	}
	_, err := systemctl("start", unitName)
	return err
}

// stopService zatrzymuje usługę; chroniona – tylko z tokenem z panelu.
func stopService(cfgPath, token string) error {
	if err := requireAdmin(lang.L("Zatrzymanie agenta", "Stopping the agent")); err != nil {
		return err
	}
	st := unitActive()
	if st == "" {
		return errNotInstalled
	}
	if st != "active" && st != "activating" && st != "reloading" {
		fmt.Println(lang.L("Agent jest już zatrzymany.", "The agent is already stopped."))
		return nil
	}
	if err := authorize(cfgPath, "stop", token); err != nil {
		return err
	}
	if _, err := systemctl("stop", unitName); err != nil {
		return err
	}
	fmt.Println(lang.L("Agent zatrzymany (uruchomienie: sudo vardr-agent start).", "Agent stopped (to start it: sudo vardr-agent start)."))
	return nil
}

// restartService uruchamia agenta ponownie w procesie usługi (SIGHUP – bez
// zatrzymywania usługi, więc także przy włączonej ochronie). Zatrzymana
// usługa – zwykły start.
func restartService() error {
	if err := requireAdmin(lang.L("Ponowne uruchomienie agenta", "Restarting the agent")); err != nil {
		return err
	}
	switch unitActive() {
	case "":
		return errNotInstalled
	case "active", "reloading":
		_, err := systemctl("kill", "--signal=SIGHUP", "--kill-whom=main", unitName)
		return err
	}
	_, err := systemctl("start", unitName)
	return err
}

// runService: proces usługi systemd. Log – rotowany plik w katalogu stanu,
// ostrzeżenia i błędy także na stderr (dziennik systemd: journalctl -u vardr-agent).
func runService(cfgPath string) {
	cfg, cfgErr := config.Load(cfgPath)
	logDir := dataDir
	level, maxMB, keep := slog.LevelInfo, 10, 3
	if cfgErr == nil {
		logDir = cfg.StateDir
		level, _ = logging.Level(cfg.Logging.Level)
		maxMB, keep = cfg.Logging.MaxSizeMB, cfg.Logging.MaxFiles
	}
	_ = os.MkdirAll(logDir, 0o700)
	handlers := logging.Tee{slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: max(level, slog.LevelWarn)})}
	if w, err := logging.OpenRotating(filepath.Join(logDir, "agent.log"), int64(maxMB)<<20, keep); err == nil {
		defer w.Close()
		handlers = append(handlers, slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	}
	log := slog.New(handlers)
	if cfgErr != nil {
		log.Error("invalid agent configuration", "config", cfgPath, "err", cfgErr)
		os.Exit(1)
	}

	// Ochrona agenta: wykrycie zabicia poprzedniego procesu, pilnowanie
	// usługi (w runAgent) i powód zatrzymania.
	g := newGuardian(cfg.StateDir, log)
	g.startup()
	svcGuard = g

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	var cancel context.CancelFunc
	done := make(chan error, 1)
	start := func(cfg *config.Config) {
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		go func() { done <- runAgent(ctx, cfg, log) }()
	}
	stop := func() bool {
		cancel()
		select {
		case <-done:
			return true
		case <-time.After(20 * time.Second):
			log.Warn("the agent did not stop within 20 s")
			return false
		}
	}
	start(cfg)
	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				// vardr-agent restart / set-server: ponowne uruchomienie w procesie
				// (chroniona usługa odmawia systemctl restart).
				c, err := config.Load(cfgPath)
				if err != nil {
					log.Error("agent restart: invalid configuration – keeping the current one", "err", err)
					continue
				}
				log.Info("agent restart requested")
				if !stop() {
					os.Exit(1) // zawieszony agent – Restart=always
				}
				start(c)
				continue
			}
			reason, ok := g.onTerm(sig)
			if !ok {
				continue
			}
			g.setStopping(reason)
			log.Info("service stop requested", "reason", reason)
			stop()
			g.cleanExit()
			return
		case err := <-done:
			// Agent zakończył się sam (np. błąd konfiguracji) – Restart=always
			// uruchomi usługę ponownie.
			log.Error("the agent stopped", "err", err)
			g.cleanExit()
			os.Exit(1)
		}
	}
}

type installOptions struct {
	server, ca, startAt string
	token, panel        string
	noStart             bool
}

// install rejestruje agenta tokenem z panelu, kopiuje program, zapisuje
// certyfikaty i konfigurację w /etc/vardr-agent i uruchamia usługę systemd.
func install(o installOptions) error {
	if err := requireAdmin(lang.L("Instalacja agenta", "Installing the agent")); err != nil {
		return err
	}
	if err := requireSystemd(); err != nil {
		return err
	}
	if st := unitActive(); st != "" {
		return fmt.Errorf(lang.L("agent jest już zainstalowany (usługa: %s).\n"+
			"  zmiana serwera:          sudo vardr-agent set-server <adres>\n"+
			"  nowa wersja programu:    sudo ./vardr-agent upgrade (z folderu nowej wersji)\n"+
			"  ponowna instalacja:      sudo vardr-agent uninstall, a potem install",
			"the agent is already installed (service: %s).\n"+
				"  change the server:       sudo vardr-agent set-server <address>\n"+
				"  new program version:     sudo ./vardr-agent upgrade (from the folder of the new version)\n"+
				"  reinstall:               sudo vardr-agent uninstall, then install"), st)
	}

	srcExe, err := os.Executable()
	if err != nil {
		return err
	}
	srcDir := filepath.Dir(srcExe)
	if o.token == "" {
		if data, err := os.ReadFile(filepath.Join(srcDir, "token.txt")); err == nil {
			o.token = strings.TrimSpace(string(data))
		}
	}
	if o.token == "" {
		return errors.New(lang.L("brak tokenu rejestracyjnego: -token <token> albo token.txt obok programu (paczka z panelu, Bifröst)",
			"no enrollment token: -token <token> or token.txt next to the program (package from the panel, Bifröst)"))
	}
	if o.ca == "" {
		o.ca = filepath.Join(srcDir, "ca.crt")
	}
	caPEM, err := os.ReadFile(o.ca)
	if err != nil {
		return fmt.Errorf(lang.L("plik CA (ca.crt obok programu albo -ca): %w", "CA file (ca.crt next to the program or -ca): %w"), err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New(lang.L("niepoprawny plik CA", "invalid CA file"))
	}
	if o.server == "" {
		if data, err := os.ReadFile(filepath.Join(srcDir, "server.txt")); err == nil {
			o.server = strings.TrimSpace(string(data))
		}
	}
	if o.server == "" {
		if o.server, err = prompt(lang.L("Adres serwera SIEM (np. 192.168.88.98 lub siem.firma.local:8443): ", "SIEM server address (e.g. 192.168.88.98 or siem.company.local:8443): ")); err != nil {
			return err
		}
	}
	serverURL, err := setup.ServerURL(o.server)
	if err != nil {
		return err
	}
	cfgText, err := setup.GenerateLinuxConfig(setup.Options{ServerURL: serverURL, StartAt: o.startAt})
	if err != nil {
		return err
	}

	// Rejestracja przed zmianami w systemie: zły token = nic nie zostaje
	// zainstalowane. Klucz powstaje tutaj i trafia tylko na ten dysk.
	panelURL := o.panel
	if panelURL == "" {
		if panelURL, err = enrollment.PanelURL(serverURL); err != nil {
			return err
		}
	}
	host, _ := os.Hostname()
	fmt.Printf(lang.L("Rejestracja agenta w panelu %s…\n", "Enrolling the agent in panel %s…\n"), panelURL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	res, keyPEM, err := enrollment.Register(ctx, panelURL, roots, o.token, enrollment.Info{Hostname: host, OS: heartbeat.OSVersion(), Version: version})
	cancel()
	if err != nil {
		return fmt.Errorf(lang.L("rejestracja agenta: %w", "agent enrollment: %w"), err)
	}
	fmt.Printf(lang.L("Zarejestrowano: agent %s (certyfikat ważny do %s)\n", "Enrolled: agent %s (certificate valid until %s)\n"), res.AgentID, res.NotAfter.Local().Format("2006-01-02"))
	fmt.Println(lang.L("Instalacja agenta Vardr", "Vardr agent installation"))

	// 1. Program.
	if srcExe != installExe {
		if err := copyFile(srcExe, installExe, 0o755); err != nil {
			return fmt.Errorf(lang.L("kopiowanie programu: %w", "copying the program: %w"), err)
		}
	}
	if why := rootOnly(installExe); why != "" {
		return fmt.Errorf(lang.L("program nie jest chroniony: %s", "the program is not protected: %s"), why)
	}
	fmt.Printf(lang.L("  [1/6] Program:       %s\n", "  [1/6] Program:       %s\n"), installExe)

	// 2. Certyfikaty (katalog tylko dla roota).
	certDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(configDir, 0o700)
	if err := os.WriteFile(filepath.Join(certDir, "ca.crt"), caPEM, 0o644); err != nil {
		return err
	}
	if err := enrollment.WritePair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), []byte(res.Certificate), keyPEM); err != nil {
		return fmt.Errorf(lang.L("zapis certyfikatu agenta: %w", "saving the agent certificate: %w"), err)
	}
	_ = os.Chmod(filepath.Join(certDir, "agent.key"), 0o600)
	client, agentID, err := shipper.NewTLSClient(filepath.Join(certDir, "ca.crt"), filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), 10*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf(lang.L("  [2/6] Certyfikaty:   %s (agent %s)\n", "  [2/6] Certificates:  %s (agent %s)\n"), certDir, agentID)

	// 3. Konfiguracja (poprzednia zostaje jako kopia) i katalog stanu.
	if _, err := os.Stat(installCfg); err == nil {
		_ = os.Rename(installCfg, installCfg+".bak")
	}
	if err := os.WriteFile(installCfg, []byte(cfgText), 0o600); err != nil {
		return err
	}
	if _, err := config.Load(installCfg); err != nil {
		return fmt.Errorf(lang.L("wygenerowana konfiguracja jest niepoprawna: %w", "the generated configuration is invalid: %w"), err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dataDir, 0o700)
	fmt.Printf(lang.L("  [3/6] Konfiguracja:  %s (serwer %s); stan: %s\n", "  [3/6] Configuration: %s (server %s); state: %s\n"), installCfg, serverURL, dataDir)

	// 4. Test połączenia – ostrzeżenie, nie przerwanie.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	connErr := shipper.CheckServer(ctx, client, serverURL)
	cancel()
	if connErr != nil {
		fmt.Printf(lang.L("  [4/6] Połączenie:    UWAGA – %v\n                       Agent będzie ponawiał połączenie; dane czekają w buforze i dzienniku.\n",
			"  [4/6] Connection:    WARNING – %v\n                       The agent will keep retrying; data waits in the buffer and the journal.\n"), connErr)
	} else {
		fmt.Println(lang.L("  [4/6] Połączenie:    OK (TLS 1.3, serwer i agent uwierzytelnieni)", "  [4/6] Connection:    OK (TLS 1.3, server and agent authenticated)"))
	}

	// 5. Usługa systemd. Znacznik instalatora: pierwszy start nie jest
	// sabotażem; ochronę (drop-in) agent włącza sam według grupy w panelu.
	markInstaller(dataDir, "install")
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if o.noStart {
		if _, err := systemctl("enable", unitName); err != nil {
			return err
		}
		fmt.Println(lang.L("  [5/6] Usługa:        "+unitName+" włączona (nie uruchomiono: -no-start)", "  [5/6] Service:       "+unitName+" enabled (not started: -no-start)"))
	} else {
		if _, err := systemctl("enable", "--now", unitName); err != nil {
			return fmt.Errorf(lang.L("usługa zarejestrowana, ale nie wystartowała: %w", "the service is registered but did not start: %w"), err)
		}
		fmt.Println(lang.L("  [5/6] Usługa:        "+unitName+" działa (start z systemem, restart po awarii)", "  [5/6] Service:       "+unitName+" running (starts with the system, restarts on failure)"))
	}

	// 6. Dziennik systemd dostępny?
	if _, err := exec.LookPath("journalctl"); err != nil {
		fmt.Println(lang.L("  [6/6] Źródła:        UWAGA – brak journalctl, dziennik systemd nie będzie czytany", "  [6/6] Sources:       WARNING – no journalctl, the systemd journal will not be read"))
	} else {
		fmt.Println(lang.L("  [6/6] Źródła:        dziennik systemd (uwierzytelnianie i ostrzeżenia)", "  [6/6] Sources:       systemd journal (authentication and warnings)"))
	}
	if _, err := os.Stat(auditd.DefaultPath); err != nil {
		fmt.Println(lang.L("                       auditd: brak – zalecany (apt install auditd / dnf install audit, potem vardr-agent audit-rules)",
			"                       auditd: missing – recommended (apt install auditd / dnf install audit, then vardr-agent audit-rules)"))
	} else {
		fmt.Println(lang.L("                       auditd: "+auditd.DefaultPath+" (zalecane reguły: vardr-agent audit-rules)",
			"                       auditd: "+auditd.DefaultPath+" (recommended rules: vardr-agent audit-rules)"))
	}
	fmt.Println(lang.L("\nGotowe. Sterowanie: sudo vardr-agent status | start | stop | restart | test | set-server <adres>",
		"\nDone. Control: sudo vardr-agent status | start | stop | restart | test | set-server <address>"))
	return nil
}

// uninstall usuwa usługę i program; klucz prywatny zawsze (ponowna
// instalacja to nowa rejestracja), z -purge także konfigurację i stan.
func uninstall(cfgPath string, purge bool, token string) error {
	if err := requireAdmin(lang.L("Odinstalowanie agenta", "Uninstalling the agent")); err != nil {
		return err
	}
	if err := authorize(cfgPath, "uninstall", token); err != nil {
		return err
	}
	if unitActive() != "" {
		if _, err := systemctl("disable", "--now", unitName); err != nil {
			return err
		}
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(dropInDir)
		_, _ = systemctl("daemon-reload")
		fmt.Println(lang.L("Usługa "+unitName+" usunięta.", "Service "+unitName+" removed."))
	}
	key := filepath.Join(configDir, "certs", "agent.key")
	if cfg, err := config.Load(cfgPath); err == nil && cfg.Server.KeyFile != "" {
		key = cfg.Server.KeyFile
	}
	if err := os.Remove(key); err == nil {
		fmt.Println(lang.L("Usunięto klucz prywatny agenta:", "Agent private key removed:"), key)
	} else if !errors.Is(err, fs.ErrNotExist) {
		fmt.Println(lang.L("UWAGA: nie usunięto klucza prywatnego", "WARNING: the private key was not removed"), key+":", err)
	}
	if purge {
		for _, d := range []string{configDir, dataDir} {
			if err := os.RemoveAll(d); err != nil {
				fmt.Println(lang.L("uwaga: nie usunięto", "warning: not removed"), d+":", err)
			}
		}
		fmt.Println(lang.L("Usunięto konfigurację, certyfikaty i stan:", "Configuration, certificates and state removed:"), configDir, dataDir)
	} else {
		fmt.Println(lang.L("Konfiguracja i bufor pozostały w", "Configuration and buffer remain in"), configDir, lang.L("i", "and"), dataDir,
			lang.L("(usuń je opcją -purge).", "(remove them with -purge)."))
	}
	if err := os.Remove(installExe); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Println(lang.L("uwaga: nie usunięto programu:", "warning: the program was not removed:"), err)
	}
	fmt.Println(lang.L("Agent odinstalowany.", "Agent uninstalled."))
	return nil
}

// upgrade podmienia program usługi na wersję, z której uruchomiono polecenie.
func upgrade(cfgPath, token string) error {
	if err := requireAdmin(lang.L("Aktualizacja agenta", "Upgrading the agent")); err != nil {
		return err
	}
	if unitActive() == "" {
		return errors.New(lang.L("agent nie jest zainstalowany – użyj sudo ./vardr-agent install", "the agent is not installed – use sudo ./vardr-agent install"))
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src == installExe {
		return fmt.Errorf(lang.L("uruchom upgrade z folderu NOWEJ wersji programu, nie z %s", "run upgrade from the folder of the NEW program version, not from %s"), installExe)
	}
	if err := authorize(cfgPath, "upgrade", token); err != nil {
		return err
	}
	if token == "" {
		markInstaller(dataDir, "upgrade") // usługa bez ochrony
	}
	fmt.Printf(lang.L("Aktualizacja agenta do wersji %s\n", "Upgrading the agent to version %s\n"), version)
	if err := copyFile(installExe, installExe+".previous", 0o755); err != nil {
		return fmt.Errorf(lang.L("kopia poprzedniej wersji: %w", "copy of the previous version: %w"), err)
	}
	// Nowy plik obok i zamiana nazwy – działający proces zachowuje stary.
	if err := copyFile(src, installExe+".new", 0o755); err != nil {
		return err
	}
	if err := os.Rename(installExe+".new", installExe); err != nil {
		return err
	}
	// Jednostka nowej wersji (np. nowe uprawnienia zapisu).
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	}
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err := systemctl("restart", unitName); err != nil {
		return fmt.Errorf(lang.L("nowa wersja nie wystartowała: %w – przywróć %s.previous", "the new version did not start: %w – restore %s.previous"), err, installExe)
	}
	fmt.Printf(lang.L("Gotowe: %s (poprzednia wersja: %s.previous), usługa uruchomiona ponownie.\n", "Done: %s (previous version: %s.previous), service restarted.\n"), installExe, installExe)
	return nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
