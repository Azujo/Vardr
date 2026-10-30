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
	"time"

	"golang.org/x/sys/windows/svc"

	"siem/agent/internal/config"
	"siem/agent/internal/logging"
	"siem/agent/internal/secure"
	"siem/agent/internal/shipper"
	"siem/agent/internal/status"
	"siem/agent/internal/winevt"
	"siem/internal/contract"
	"siem/internal/lang"
)

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
