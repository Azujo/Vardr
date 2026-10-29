// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

// Command vardr-agent (Linux) zbiera wpisy z dziennika systemd i wysyła je
// po mTLS do serwera SIEM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"siem/agent/internal/auditd"
	"siem/agent/internal/config"
	"siem/agent/internal/journald"
	"siem/agent/internal/logfile"
	"siem/agent/internal/logging"
	"siem/agent/internal/shipper"
	"siem/agent/internal/status"
	"siem/internal/lang"
)

const version = "0.11.0"

func usage() {
	if lang.Local() == "en" {
		fmt.Fprintf(os.Stderr, usageEn, version, installCfg)
		return
	}
	fmt.Fprintf(os.Stderr, `vardr-agent %s – agent SIEM dla Linuksa (systemd)

Instalacja (jako root, w folderze z vardr-agent, ca.crt i token.txt z panelu):
  sudo ./vardr-agent install [-server adres] [-token token] [-start-at now|oldest] [-no-start]
      -server   adres serwera, np. 192.168.88.98 lub siem.firma.local:8443
                (bez -server: z pliku server.txt albo pytanie)
      -token    token rejestracyjny z panelu (Bifröst; w paczce – token.txt)
      -ca       inne położenie ca.crt

Sterowanie (jako root):
  vardr-agent status                 stan usługi, połączenia, źródeł i limitów
  vardr-agent start | restart
  vardr-agent stop [-token T]        zatrzymanie (agent chroniony: token z panelu)
  vardr-agent test                   sprawdzenie połączenia z serwerem
  vardr-agent set-server <adres>     zmiana adresu serwera (restartuje agenta)
  ./vardr-agent upgrade [-token T]   aktualizacja programu (uruchom z folderu nowej wersji)
  vardr-agent uninstall [-token T] [-purge]
                                    odinstalowanie (-purge: także konfiguracja i stan)

Ochrona (włączana w grupie agentów w panelu): systemctl stop i restart
odmawiają, zatrzymanie, aktualizacja i deinstalacja tylko z jednorazowym
tokenem z panelu (Huginn → agent → Token deinstalacji); próby bez tokenu,
kill i zmiany usługi trafiają do panelu jako alert.

Diagnostyka:
  vardr-agent check                  walidacja konfiguracji, certyfikatów i uprawnień
  vardr-agent audit-rules            zalecane reguły auditd, instalacja:
      vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules && sudo augenrules --load
  vardr-agent run                    uruchomienie w konsoli zamiast usługi (Ctrl+C kończy)
  vardr-agent enroll -server <adres> -token <token> -dir <katalog>
                                    rejestracja bez instalacji usługi (test, konsola)
  vardr-agent version

Pliki: program %s, konfiguracja i certyfikaty /etc/vardr-agent,
stan, bufor i log /var/lib/vardr-agent, log usługi także: journalctl -u vardr-agent.
Opcja -config <plik> (przed lub po poleceniu) wskazuje inną konfigurację.
`, version, installExe)
}

const usageEn = `vardr-agent %s – SIEM agent for Linux (systemd)

Installation (as root, in the folder with vardr-agent, ca.crt and token.txt from the panel):
  sudo ./vardr-agent install [-server address] [-token token] [-start-at now|oldest] [-no-start]
      -server   server address, e.g. 192.168.88.98 or siem.company.local:8443
                (without -server: from server.txt or a prompt)
      -token    enrollment token from the panel (Bifröst; in the package – token.txt)
      -ca       another location of ca.crt

Control (as root):
  vardr-agent status                 state of the service, connection, sources and limits
  vardr-agent start | restart
  vardr-agent stop [-token T]        stop (protected agent: token from the panel)
  vardr-agent test                   check the connection to the server
  vardr-agent set-server <address>   change the server address (restarts the agent)
  ./vardr-agent upgrade [-token T]   upgrade the program (run from the folder of the new version)
  vardr-agent uninstall [-token T] [-purge]
                                    uninstall (-purge: also configuration and state)

Protection (enabled in the agent group in the panel): systemctl stop and restart
refuse, stopping, upgrading and uninstalling only with a one-time token from
the panel (Huginn → agent → Uninstall token); attempts without a token, kill
and service changes reach the panel as an alert.

Diagnostics:
  vardr-agent check                  validate the configuration, certificates and permissions
  vardr-agent audit-rules            recommended auditd rules, installation:
      vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules && sudo augenrules --load
  vardr-agent run                    run in the console instead of as a service (Ctrl+C stops)
  vardr-agent enroll -server <address> -token <token> -dir <directory>
                                    enroll without installing the service (test, console)
  vardr-agent version

Default configuration: %s. The -config <file> option (before or after the command) points to another one.
Messages follow LANG (VARDR_LANG=pl|en overrides it).
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
	token := new(string)
	switch cmd {
	case "install":
		cf.StringVar(&opts.server, "server", "", lang.L("adres serwera", "server address"))
		cf.StringVar(&opts.token, "token", "", lang.L("token rejestracyjny z panelu", "enrollment token from the panel"))
		cf.StringVar(&opts.panel, "panel", "", lang.L("adres panelu do rejestracji (domyślnie https://<serwer>:8444)", "panel address for enrollment (default https://<server>:8444)"))
		cf.StringVar(&opts.startAt, "start-at", "now", "now | oldest")
		cf.StringVar(&opts.ca, "ca", "", lang.L("plik CA", "CA file"))
		cf.BoolVar(&opts.noStart, "no-start", false, lang.L("nie uruchamiaj usługi po instalacji", "do not start the service after installation"))
	case "uninstall":
		purge = cf.Bool("purge", false, lang.L("usuń także konfigurację, certyfikaty i stan", "also remove configuration, certificates and state"))
		token = cf.String("token", "", lang.L("token deinstalacji z panelu (agent chroniony)", "uninstall token from the panel (protected agent)"))
	case "stop", "upgrade":
		token = cf.String("token", "", lang.L("token deinstalacji z panelu (agent chroniony)", "uninstall token from the panel (protected agent)"))
	case "enroll":
		cf.StringVar(&eo.server, "server", "", lang.L("adres serwera", "server address"))
		cf.StringVar(&eo.token, "token", "", lang.L("token rejestracyjny z panelu", "enrollment token from the panel"))
		cf.StringVar(&eo.ca, "ca", "", lang.L("plik głównego CA (domyślnie ca.crt obok programu)", "root CA file (default ca.crt next to the program)"))
		cf.StringVar(&eo.panel, "panel", "", lang.L("adres panelu (domyślnie https://<serwer>:8444)", "panel address (default https://<server>:8444)"))
		cf.StringVar(&eo.dir, "dir", "", lang.L("katalog na certyfikaty i agent.yaml", "directory for certificates and agent.yaml"))
	}
	_ = cf.Parse(rest)
	if *cfgPath == "" {
		*cfgPath = defaultConfigPath()
	}

	var err error
	switch cmd {
	case "service": // uruchamiane przez systemd (ExecStart)
		runService(*cfgPath)
		return
	case "install":
		err = install(opts)
	case "uninstall":
		err = uninstall(*cfgPath, *purge, *token)
	case "upgrade":
		err = upgrade(*cfgPath, *token)
	case "enroll":
		err = enrollOnly(eo)
	case "start":
		err = startService()
	case "stop":
		err = stopService(*cfgPath, *token)
	case "restart":
		err = restartService()
	case "status":
		err = showStatus(*cfgPath)
	case "test":
		err = testConnection(*cfgPath)
	case "set-server":
		if cf.NArg() != 1 {
			err = errors.New(lang.L("użycie: sudo vardr-agent set-server <adres>, np. sudo vardr-agent set-server 192.168.88.98",
				"usage: sudo vardr-agent set-server <address>, e.g. sudo vardr-agent set-server 192.168.88.98"))
		} else {
			err = setServer(*cfgPath, cf.Arg(0))
		}
	case "check":
		err = check(*cfgPath)
	case "run":
		err = runConsole(*cfgPath)
	case "audit-rules":
		fmt.Print(auditd.Rules)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	fmt.Printf(lang.L("  klucz:     %s – %s\n", "  key:       %s – %s\n"), cfg.Server.KeyFile, modeText(cfg.Server.KeyFile, 0o077))
	if fi, err := os.Stat(cfg.StateDir); err == nil && fi.IsDir() {
		fmt.Printf(lang.L("  stan:      %s – %s\n", "  state:     %s – %s\n"), cfg.StateDir, modeText(cfg.StateDir, 0o077))
	}
	exe, _ := os.Executable()
	if why := rootOnly(exe); why == "" {
		fmt.Printf(lang.L("  program:   %s – chroniony (root, bez zapisu dla innych)\n", "  program:   %s – protected (root, not writable by others)\n"), exe)
	} else {
		fmt.Printf(lang.L("  program:   UWAGA – %s\n", "  program:   WARNING – %s\n"), why)
	}
	if j := cfg.Journald; j.Enabled {
		bin := j.Journalctl
		if bin == "" {
			bin = "journalctl"
		}
		if p, err := exec.LookPath(bin); err != nil {
			fmt.Printf(lang.L("  journald:  UWAGA – brak %s\n", "  journald:  WARNING – %s not found\n"), bin)
		} else {
			s := &journald.Source{Filter: journald.Filter{All: j.All, Units: j.Units, Identifiers: j.Identifiers}}
			fmt.Printf("  journald:  %s %v\n", p, s.Filter.Matches())
		}
	}
	if a := cfg.Auditd; a.Enabled {
		p := a.Path
		if p == "" {
			p = auditd.DefaultPath
		}
		var ex []string
		for t := range auditExclude(a) {
			ex = append(ex, t)
		}
		sort.Strings(ex)
		switch f, err := os.Open(p); {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Printf(lang.L("  auditd:    brak %s – agent poczeka na plik (zainstaluj auditd: apt install auditd / dnf install audit)\n",
				"  auditd:    %s not found – the agent will wait for the file (install auditd: apt install auditd / dnf install audit)\n"), p)
		case err != nil:
			fmt.Printf(lang.L("  auditd:    UWAGA – %v (uruchom check przez sudo)\n", "  auditd:    WARNING – %v (run check with sudo)\n"), err)
		default:
			f.Close()
			fmt.Printf(lang.L("  auditd:    %s, pomijane typy: %s\n", "  auditd:    %s, excluded types: %s\n"), p, strings.Join(ex, " "))
		}
	}
	for _, fc := range cfg.Files {
		paths := logfile.Expand([]string{fc.Path}, cfg.StateDir)
		if len(paths) == 0 {
			fmt.Printf(lang.L("  plik:      %s – brak pasujących plików (wzorzec sprawdzany przy starcie agenta)\n",
				"  file:      %s – no matching files (the pattern is checked when the agent starts)\n"), fc.Path)
		}
		for _, p := range paths {
			app := fc.App
			if app == "" {
				app = logfile.AppName(p)
			}
			switch f, err := os.Open(p); {
			case errors.Is(err, fs.ErrNotExist):
				fmt.Printf(lang.L("  plik:      brak %s – agent poczeka na plik\n", "  file:      %s not found – the agent will wait for the file\n"), p)
			case err != nil:
				fmt.Printf(lang.L("  plik:      UWAGA – %v (uruchom check przez sudo)\n", "  file:      WARNING – %v (run check with sudo)\n"), err)
			default:
				f.Close()
				fmt.Printf(lang.L("  plik:      %s (app %s)\n", "  file:      %s (app %s)\n"), p, app)
			}
		}
	}
	return nil
}

// modeText: uprawnienia pliku – w porządku, gdy nikt poza właścicielem
// (bity mask) nie ma dostępu, a właścicielem jest root.
func modeText(path string, mask fs.FileMode) string {
	fi, err := os.Stat(path)
	if err != nil {
		return lang.L("nie można sprawdzić: ", "cannot check: ") + errText(err)
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().Perm()&mask != 0 || (st != nil && st.Uid != 0) {
		return fmt.Sprintf(lang.L("UWAGA: %v, właściciel uid %d – dostęp powinien mieć tylko root", "WARNING: %v, owner uid %d – only root should have access"), fi.Mode().Perm(), st.Uid)
	}
	return lang.L("chroniony (tylko root)", "protected (root only)")
}

func showStatus(cfgPath string) error {
	switch st := unitActive(); st {
	case "":
		fmt.Println(lang.L("Usługa "+unitName+": nie jest zainstalowana", "Service "+unitName+": not installed"))
	default:
		pid, _ := systemctl("show", "-p", "MainPID", "--value", unitName)
		fmt.Printf(lang.L("Usługa %s: %s", "Service %s: %s"), unitName, st)
		if pid != "" && pid != "0" {
			fmt.Printf(" (PID %s)", pid)
		}
		fmt.Println()
	}
	cfg, err := config.Load(cfgPath)
	if errors.Is(err, fs.ErrPermission) {
		fmt.Println(lang.L("\nSzczegóły (połączenie, źródła, liczniki) są dostępne tylko dla roota – uruchom przez sudo.",
			"\nDetails (connection, sources, counters) are available to root only – run it with sudo."))
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
		fmt.Println(lang.L("\nSzczegóły są dostępne tylko dla roota – uruchom przez sudo.", "\nDetails are available to root only – run it with sudo."))
		return nil
	case err != nil:
		return err
	}
	fmt.Println()
	status.Render(os.Stdout, s, time.Now())
	return nil
}
