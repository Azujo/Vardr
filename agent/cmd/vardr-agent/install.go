// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/agent/internal/config"
	"siem/agent/internal/enrollment"
	"siem/agent/internal/heartbeat"
	"siem/agent/internal/logging"
	"siem/agent/internal/secure"
	"siem/agent/internal/setup"
	"siem/agent/internal/shipper"
	"siem/internal/lang"
)

// Docelowe lokalizacje instalacji.
var (
	installDir = filepath.Join(os.Getenv("ProgramFiles"), "SiemAgent")
	dataDir    = filepath.Join(os.Getenv("ProgramData"), "SiemAgent")
	installExe = filepath.Join(installDir, "vardr-agent.exe")
	// legacyExe: program agenta do wersji 0.7.x (przed zmianą nazwy na Vardr).
	legacyExe  = filepath.Join(installDir, "siem_agent.exe")
	installCfg = filepath.Join(dataDir, "agent.yaml")
)

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

type installOptions struct {
	server, ca, cert, key, profile, startAt string
	token, panel                            string // rejestracja tokenem (Bifröst)
	noStart                                 bool
}

func install(o installOptions) error {
	if err := requireAdmin(lang.L("Instalacja agenta", "Installing the agent")); err != nil {
		return err
	}
	if st, err := queryService(); err == nil {
		return fmt.Errorf(lang.L("agent jest już zainstalowany (usługa: %s).\n"+
			"  zmiana serwera:          vardr-agent set-server <adres>\n"+
			"  nowa wersja programu:    vardr-agent upgrade (uruchomione z folderu nowej wersji)\n"+
			"  ponowna instalacja:      vardr-agent uninstall, a potem install",
			"the agent is already installed (service: %s).\n"+
				"  change the server:       vardr-agent set-server <address>\n"+
				"  new program version:     vardr-agent upgrade (run from the folder of the new version)\n"+
				"  reinstall:               vardr-agent uninstall, then install"), stateName(st.State))
	}

	srcExe, err := os.Executable()
	if err != nil {
		return err
	}
	srcDir := filepath.Dir(srcExe)
	pick := func(flagVal, name string) string {
		if flagVal != "" {
			return flagVal
		}
		return filepath.Join(srcDir, name)
	}
	// Paczka z panelu (Bifröst) zawiera token zamiast certyfikatu i klucza:
	// agent zarejestruje się sam, generując klucz u siebie.
	if o.token == "" {
		if data, err := os.ReadFile(filepath.Join(srcDir, "token.txt")); err == nil {
			o.token = strings.TrimSpace(string(data))
		}
	}
	enrolling := o.token != "" && o.cert == "" && o.key == "" && !fileExists(filepath.Join(srcDir, "agent.crt"))
	o.ca, o.cert, o.key = pick(o.ca, "ca.crt"), pick(o.cert, "agent.crt"), pick(o.key, "agent.key")

	// Weryfikacja WSZYSTKIEGO przed jakąkolwiek zmianą w systemie – błąd
	// w tym miejscu nie zostawia połowicznej instalacji.
	if enrolling {
		if err := checkPackage(srcDir, o.ca); err != nil {
			return err
		}
	} else {
		if err := checkPackage(srcDir, o.ca, o.cert, o.key); err != nil {
			return err
		}
		if _, agentID, err := shipper.NewTLSClient(o.ca, o.cert, o.key, 10*time.Second); err != nil {
			return fmt.Errorf(lang.L("certyfikaty z paczki są niepoprawne: %w", "the package certificates are invalid: %w"), err)
		} else {
			fmt.Println(lang.L("Paczka instalacyjna agenta:", "Agent installation package:"), agentID)
		}
	}

	if o.server == "" {
		// Paczka z siem-pki może zawierać domyślny adres serwera.
		if data, err := os.ReadFile(filepath.Join(srcDir, "server.txt")); err == nil {
			o.server = strings.TrimSpace(string(data))
			if o.server != "" {
				fmt.Println(lang.L("Adres serwera z pliku server.txt:", "Server address from server.txt:"), o.server)
			}
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

	// Rejestracja tokenem – też przed zmianami w systemie (zły token = nic
	// nie zostaje zainstalowane). Klucz powstaje tutaj i trafia tylko na dysk
	// tego komputera.
	var enrolled *enrollment.Result
	var enrolledKey []byte
	if enrolling {
		panelURL := o.panel
		if panelURL == "" {
			if panelURL, err = enrollment.PanelURL(serverURL); err != nil {
				return err
			}
		}
		caPEM, err := os.ReadFile(o.ca)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return errors.New(lang.L("ca.crt z paczki jest niepoprawny", "ca.crt in the package is invalid"))
		}
		host, _ := os.Hostname()
		fmt.Printf(lang.L("Rejestracja agenta w panelu %s tokenem z paczki…\n", "Enrolling the agent in panel %s with the package token…\n"), panelURL)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		res, key, err := enrollment.Register(ctx, panelURL, roots, o.token, enrollment.Info{Hostname: host, OS: heartbeat.OSVersion(), Version: version})
		cancel()
		if err != nil {
			return fmt.Errorf(lang.L("rejestracja agenta: %w", "agent enrollment: %w"), err)
		}
		enrolled, enrolledKey = &res, key
		fmt.Printf(lang.L("Zarejestrowano: agent %s (certyfikat ważny do %s)\n", "Enrolled: agent %s (certificate valid until %s)\n"), res.AgentID, res.NotAfter.Local().Format("2006-01-02"))
	}
	if o.profile == "" {
		o.profile = "workstation"
		if enrolled != nil && enrolled.Profile != "" {
			o.profile = enrolled.Profile // profil przypisany do tokenu w panelu
		}
	}
	cfgText, err := setup.GenerateConfig(setup.Options{ServerURL: serverURL, Profile: o.profile, StartAt: o.startAt})
	if err != nil {
		return err
	}

	fmt.Println(lang.L("Instalacja agenta SIEM", "SIEM agent installation"))

	// 1. Program w folderze dostępnym do zapisu tylko dla administratorów.
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if !samePath(srcExe, installExe) {
		if err := copyFile(srcExe, installExe); err != nil {
			return fmt.Errorf(lang.L("kopiowanie programu: %w", "copying the program: %w"), err)
		}
	}
	if ok, why := secure.ServiceBinarySafe(installExe); !ok {
		return fmt.Errorf(lang.L("folder programu nie jest chroniony: %s", "the program folder is not protected: %s"), why)
	}
	fmt.Printf(lang.L("  [1/7] Program:       %s\n", "  [1/7] Program:       %s\n"), installExe)

	// 2. Certyfikaty agenta.
	certDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := secure.RestrictDir(dataDir); err != nil {
		return err
	}
	files := [][2]string{{o.ca, "ca.crt"}, {o.cert, "agent.crt"}, {o.key, "agent.key"}}
	if enrolled != nil {
		files = files[:1] // tylko CA – certyfikat i klucz z rejestracji zapisujemy niżej
		if err := enrollment.WritePair(filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"),
			[]byte(enrolled.Certificate), enrolledKey); err != nil {
			return fmt.Errorf(lang.L("zapis certyfikatu agenta: %w", "saving the agent certificate: %w"), err)
		}
	}
	for _, f := range files {
		src, name := f[0], f[1]
		dst := filepath.Join(certDir, name)
		if samePath(src, dst) {
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf(lang.L("kopiowanie certyfikatu %s: %w", "copying certificate %s: %w"), name, err)
		}
	}
	client, agentID, err := shipper.NewTLSClient(filepath.Join(certDir, "ca.crt"),
		filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), 10*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf(lang.L("  [2/7] Certyfikaty:   %s (agent %s)\n", "  [2/7] Certificates:  %s (agent %s)\n"), certDir, agentID)

	// 3. Konfiguracja (poprzednia zostaje jako kopia).
	if _, err := os.Stat(installCfg); err == nil {
		_ = os.Rename(installCfg, installCfg+".bak")
	}
	if err := os.WriteFile(installCfg, []byte(cfgText), 0o600); err != nil {
		return err
	}
	if _, err := config.Load(installCfg); err != nil {
		return fmt.Errorf(lang.L("wygenerowana konfiguracja jest niepoprawna: %w", "the generated configuration is invalid: %w"), err)
	}
	fmt.Printf(lang.L("  [3/7] Konfiguracja:  %s (serwer %s, profil %s)\n", "  [3/7] Configuration: %s (server %s, profile %s)\n"), installCfg, serverURL, o.profile)

	// 4. Uprawnienia: dane, konfiguracja i klucz tylko dla SYSTEM i Administratorów.
	if err := secure.RestrictDir(dataDir); err != nil {
		return err
	}
	fmt.Println(lang.L("  [4/7] Uprawnienia:   dane i klucz dostępne tylko dla SYSTEM i Administratorów", "  [4/7] Permissions:   data and key accessible to SYSTEM and Administrators only"))

	// 5. Test połączenia – ostrzeżenie, nie przerwanie (serwer może być chwilowo niedostępny).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	connErr := shipper.CheckServer(ctx, client, serverURL)
	cancel()
	if connErr != nil {
		fmt.Printf(lang.L("  [5/7] Połączenie:    UWAGA – %v\n"+
			"                       Agent będzie ponawiał połączenie; dane czekają w dzienniku Windows.\n",
			"  [5/7] Connection:    WARNING – %v\n"+
				"                       The agent will keep retrying; data waits in the Windows event log.\n"), connErr)
	} else {
		fmt.Println(lang.L("  [5/7] Połączenie:    OK (TLS 1.3, serwer i agent uwierzytelnieni)", "  [5/7] Connection:    OK (TLS 1.3, server and agent authenticated)"))
	}

	// 6. Usługa Windows + źródło w Podglądzie zdarzeń.
	if err := logging.InstallEventSource(serviceName); err != nil {
		fmt.Fprintln(os.Stderr, lang.L("  uwaga: nie zarejestrowano źródła w dzienniku zdarzeń:", "  warning: the event log source was not registered:"), err)
	}
	if err := registerService(installExe, installCfg); err != nil {
		return err
	}
	markInstaller(dataDir, "install")
	if o.noStart {
		fmt.Println(lang.L("  [6/7] Usługa:        zarejestrowana (nie uruchomiono: -no-start)", "  [6/7] Service:       registered (not started: -no-start)"))
	} else {
		if err := withService(func(s *mgr.Service) error {
			if err := s.Start(); err != nil {
				return err
			}
			return waitState(s, svc.Running, 15*time.Second)
		}); err != nil {
			return fmt.Errorf(lang.L("usługa zarejestrowana, ale nie wystartowała: %w", "the service is registered but did not start: %w"), err)
		}
		fmt.Println(lang.L("  [6/7] Usługa:        SiemAgent działa (start automatyczny, restart po awarii)", "  [6/7] Service:       SiemAgent running (automatic start, restart on failure)"))
	}

	// 7. Polecenie vardr-agent dostępne z każdego miejsca.
	if err := addToSystemPath(installDir); err != nil {
		fmt.Printf(lang.L("  [7/7] PATH:          UWAGA – %v\n", "  [7/7] PATH:          WARNING – %v\n"), err)
	} else {
		fmt.Printf(lang.L("  [7/7] PATH:          dodano %s\n", "  [7/7] PATH:          added %s\n"), installDir)
	}

	fmt.Println(lang.L("\nGotowe. Otwórz NOWE okno PowerShell lub cmd (jako administrator) i użyj:", "\nDone. Open a NEW PowerShell or cmd window (as administrator) and use:"))
	fmt.Println(lang.L("  vardr-agent status | start | stop | restart | test | set-server <adres>", "  vardr-agent status | start | stop | restart | test | set-server <address>"))
	return nil
}

// uninstall usuwa usługę, wpis w PATH i program. Z -purge usuwa też dane,
// konfigurację, certyfikaty i kopię stanu w rejestrze.
// removeAgentKey usuwa klucz prywatny agenta przy deinstalacji. Panel
// unieważnia certyfikat (deinstalacja tokenem), ale klucz nie może zostać na
// dysku – sprzedany albo przekazany komputer, kopia dysku. Ponowna
// instalacja na tym komputerze to nowa rejestracja tokenem.
func removeAgentKey(cfgPath string) {
	key := filepath.Join(dataDir, "certs", "agent.key")
	if cfg, err := config.Load(cfgPath); err == nil && cfg.Server.KeyFile != "" {
		key = cfg.Server.KeyFile
	}
	switch err := os.Remove(key); {
	case err == nil:
		fmt.Println(lang.L("Usunięto klucz prywatny agenta:", "Agent private key removed:"), key)
	case !errors.Is(err, fs.ErrNotExist):
		fmt.Println(lang.L("UWAGA: nie usunięto klucza prywatnego", "WARNING: the private key was not removed"), key+":", err)
	}
}

func uninstall(cfgPath string, purge bool, token string) error {
	if err := requireAdmin(lang.L("Odinstalowanie agenta", "Uninstalling the agent")); err != nil {
		return err
	}
	if err := authorize(cfgPath, "uninstall", token); err != nil {
		return err
	}
	if err := deleteService(); err != nil && !errors.Is(err, errNotInstalled) {
		return err
	}
	fmt.Println(lang.L("Usługa SiemAgent usunięta.", "SiemAgent service removed."))
	_ = logging.RemoveEventSource(serviceName)

	if err := removeFromSystemPath(installDir); err != nil {
		fmt.Println(lang.L("uwaga: PATH:", "warning: PATH:"), err)
	}

	if !purge {
		removeAgentKey(cfgPath)
	}
	if purge {
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Println(lang.L("uwaga: nie usunięto danych:", "warning: data not removed:"), err)
		} else {
			fmt.Println(lang.L("Usunięto dane, konfigurację i certyfikaty:", "Data, configuration and certificates removed:"), dataDir)
		}
		// Klucze rejestru usuwa się od najgłębszych (DeleteKey nie usuwa podkluczy).
		for _, k := range listInstances() {
			_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent\Instances\`+k)
		}
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent\Instances`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent`)
	} else {
		fmt.Println(lang.L("Konfiguracja i bufor pozostały w", "Configuration and buffer remain in"), dataDir, lang.L("(usuń je opcją -purge); klucz prywatny usunięty.", "(remove them with -purge); private key removed."))
	}

	// Usunięcie folderu programu. Jeśli polecenie działa z tego folderu,
	// plik jest w użyciu – usuwamy go chwilę po zakończeniu procesu.
	exe, _ := os.Executable()
	if strings.HasPrefix(strings.ToLower(exe), strings.ToLower(installDir)) {
		cmd := exec.Command("cmd.exe", "/C", `ping -n 4 127.0.0.1 >NUL & rmdir /S /Q "`+installDir+`"`)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
			CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS}
		if err := cmd.Start(); err != nil {
			fmt.Println(lang.L("uwaga: usuń ręcznie folder", "warning: remove the folder manually"), installDir)
		}
	} else if err := os.RemoveAll(installDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Println(lang.L("uwaga: nie usunięto folderu programu:", "warning: the program folder was not removed:"), err)
	}
	fmt.Println(lang.L("Agent odinstalowany.", "Agent uninstalled."))
	return nil
}

func listInstances() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent\Instances`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	return names
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
	if st, err := queryService(); err == nil && st.State == svc.Running {
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && strings.EqualFold(aa, bb)
}

// --- PATH systemowy ---

func addToSystemPath(dir string) error {
	return editSystemPath(func(p string) (string, bool) { return setup.AddToPath(p, dir) })
}

func removeFromSystemPath(dir string) error {
	return editSystemPath(func(p string) (string, bool) { return setup.RemoveFromPath(p, dir) })
}

func editSystemPath(edit func(string) (string, bool)) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	next, changed := edit(cur)
	if !changed {
		return nil
	}
	if err := k.SetExpandStringValue("Path", next); err != nil {
		return err
	}
	broadcastEnvironmentChange()
	return nil
}

// broadcastEnvironmentChange informuje Eksploratora i nowe okna konsoli
// o zmianie zmiennych środowiskowych.
func broadcastEnvironmentChange() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	send := user32.NewProc("SendMessageTimeoutW")
	env, _ := windows.UTF16PtrFromString("Environment")
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001A, 0x0002
	var result uintptr
	send.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000,
		uintptr(unsafe.Pointer(&result)))
}

// checkPackage sprawdza, czy obok programu (lub we wskazanych miejscach)
// są pliki paczki instalacyjnej, i podpowiada, skąd je wziąć.
func checkPackage(srcDir string, files ...string) error {
	var missing []string
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if lang.Local() == "en" {
		return fmt.Errorf("installation package files are missing:\n  %s\n\n"+
			"Installation is run from the folder of a package created for this computer, e.g.:\n"+
			`  bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98`+"\n"+
			`  cd dist\agt-pc01`+"\n"+
			`  .\vardr-agent.exe install`+"\n"+
			"(or point to the files with -ca, -cert, -key). Folder %s does not contain a package.",
			strings.Join(missing, "\n  "), srcDir)
	}
	return fmt.Errorf("brak plików paczki instalacyjnej:\n  %s\n\n"+
		"Instalację uruchamia się z folderu paczki utworzonej dla tego komputera, np.:\n"+
		`  bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98`+"\n"+
		`  cd dist\agt-pc01`+"\n"+
		`  .\vardr-agent.exe install`+"\n"+
		"(albo wskaż pliki opcjami -ca, -cert, -key). Folder %s nie zawiera paczki.",
		strings.Join(missing, "\n  "), srcDir)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
