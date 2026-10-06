//go:build windows

package main

import (
	"bufio"
	"context"
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

	"siem/internal/agent/config"
	"siem/internal/agent/logging"
	"siem/internal/agent/secure"
	"siem/internal/agent/setup"
	"siem/internal/agent/shipper"
)

// Docelowe lokalizacje instalacji.
var (
	installDir = filepath.Join(os.Getenv("ProgramFiles"), "SiemAgent")
	dataDir    = filepath.Join(os.Getenv("ProgramData"), "SiemAgent")
	installExe = filepath.Join(installDir, "siem_agent.exe")
	installCfg = filepath.Join(dataDir, "agent.yaml")
)

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

type installOptions struct {
	server, ca, cert, key, profile, startAt string
	noStart                                 bool
}

func install(o installOptions) error {
	if err := requireAdmin("Instalacja agenta"); err != nil {
		return err
	}
	if st, err := queryService(); err == nil {
		return fmt.Errorf("agent jest już zainstalowany (usługa: %s).\n"+
			"  zmiana serwera:          siem_agent set-server <adres>\n"+
			"  ponowna instalacja:      siem_agent uninstall, a potem install", stateNames[st.State])
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
	o.ca, o.cert, o.key = pick(o.ca, "ca.crt"), pick(o.cert, "agent.crt"), pick(o.key, "agent.key")

	// Weryfikacja WSZYSTKIEGO przed jakąkolwiek zmianą w systemie – błąd
	// w tym miejscu nie zostawia połowicznej instalacji.
	if err := checkPackage(srcDir, o.ca, o.cert, o.key); err != nil {
		return err
	}
	if _, agentID, err := shipper.NewTLSClient(o.ca, o.cert, o.key, 10*time.Second); err != nil {
		return fmt.Errorf("certyfikaty z paczki są niepoprawne: %w", err)
	} else {
		fmt.Println("Paczka instalacyjna agenta:", agentID)
	}

	if o.server == "" {
		// Paczka z siem-pki może zawierać domyślny adres serwera.
		if data, err := os.ReadFile(filepath.Join(srcDir, "server.txt")); err == nil {
			o.server = strings.TrimSpace(string(data))
			if o.server != "" {
				fmt.Println("Adres serwera z pliku server.txt:", o.server)
			}
		}
	}
	if o.server == "" {
		if o.server, err = prompt("Adres serwera SIEM (np. 192.168.88.98 lub siem.firma.local:8443): "); err != nil {
			return err
		}
	}
	serverURL, err := setup.ServerURL(o.server)
	if err != nil {
		return err
	}
	cfgText, err := setup.GenerateConfig(setup.Options{ServerURL: serverURL, Profile: o.profile, StartAt: o.startAt})
	if err != nil {
		return err
	}

	fmt.Println("Instalacja agenta SIEM")

	// 1. Program w folderze dostępnym do zapisu tylko dla administratorów.
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if !samePath(srcExe, installExe) {
		if err := copyFile(srcExe, installExe); err != nil {
			return fmt.Errorf("kopiowanie programu: %w", err)
		}
	}
	if ok, why := secure.ServiceBinarySafe(installExe); !ok {
		return fmt.Errorf("folder programu nie jest chroniony: %s", why)
	}
	fmt.Printf("  [1/7] Program:       %s\n", installExe)

	// 2. Certyfikaty agenta.
	certDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return err
	}
	if err := secure.RestrictDir(dataDir); err != nil {
		return err
	}
	for _, f := range [][2]string{{o.ca, "ca.crt"}, {o.cert, "agent.crt"}, {o.key, "agent.key"}} {
		src, name := f[0], f[1]
		dst := filepath.Join(certDir, name)
		if samePath(src, dst) {
			continue
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("kopiowanie certyfikatu %s: %w", name, err)
		}
	}
	client, agentID, err := shipper.NewTLSClient(filepath.Join(certDir, "ca.crt"),
		filepath.Join(certDir, "agent.crt"), filepath.Join(certDir, "agent.key"), 10*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("  [2/7] Certyfikaty:   %s (agent %s)\n", certDir, agentID)

	// 3. Konfiguracja (poprzednia zostaje jako kopia).
	if _, err := os.Stat(installCfg); err == nil {
		_ = os.Rename(installCfg, installCfg+".bak")
	}
	if err := os.WriteFile(installCfg, []byte(cfgText), 0o600); err != nil {
		return err
	}
	if _, err := config.Load(installCfg); err != nil {
		return fmt.Errorf("wygenerowana konfiguracja jest niepoprawna: %w", err)
	}
	fmt.Printf("  [3/7] Konfiguracja:  %s (serwer %s, profil %s)\n", installCfg, serverURL, o.profile)

	// 4. Uprawnienia: dane, konfiguracja i klucz tylko dla SYSTEM i Administratorów.
	if err := secure.RestrictDir(dataDir); err != nil {
		return err
	}
	fmt.Println("  [4/7] Uprawnienia:   dane i klucz dostępne tylko dla SYSTEM i Administratorów")

	// 5. Test połączenia – ostrzeżenie, nie przerwanie (serwer może być chwilowo niedostępny).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	connErr := shipper.CheckServer(ctx, client, serverURL)
	cancel()
	if connErr != nil {
		fmt.Printf("  [5/7] Połączenie:    UWAGA – %v\n"+
			"                       Agent będzie ponawiał połączenie; dane czekają w dzienniku Windows.\n", connErr)
	} else {
		fmt.Println("  [5/7] Połączenie:    OK (TLS 1.3, serwer i agent uwierzytelnieni)")
	}

	// 6. Usługa Windows + źródło w Podglądzie zdarzeń.
	if err := logging.InstallEventSource(serviceName); err != nil {
		fmt.Fprintln(os.Stderr, "  uwaga: nie zarejestrowano źródła w dzienniku zdarzeń:", err)
	}
	if err := registerService(installExe, installCfg); err != nil {
		return err
	}
	if o.noStart {
		fmt.Println("  [6/7] Usługa:        zarejestrowana (nie uruchomiono: -no-start)")
	} else {
		if err := withService(func(s *mgr.Service) error {
			if err := s.Start(); err != nil {
				return err
			}
			return waitState(s, svc.Running, 15*time.Second)
		}); err != nil {
			return fmt.Errorf("usługa zarejestrowana, ale nie wystartowała: %w", err)
		}
		fmt.Println("  [6/7] Usługa:        SiemAgent działa (start automatyczny, restart po awarii)")
	}

	// 7. Polecenie siem_agent dostępne z każdego miejsca.
	if err := addToSystemPath(installDir); err != nil {
		fmt.Printf("  [7/7] PATH:          UWAGA – %v\n", err)
	} else {
		fmt.Printf("  [7/7] PATH:          dodano %s\n", installDir)
	}

	fmt.Println("\nGotowe. Otwórz NOWE okno PowerShell lub cmd (jako administrator) i użyj:")
	fmt.Println("  siem_agent status | start | stop | restart | test | set-server <adres>")
	return nil
}

// uninstall usuwa usługę, wpis w PATH i program. Z -purge usuwa też dane,
// konfigurację, certyfikaty i kopię stanu w rejestrze.
func uninstall(purge bool) error {
	if err := requireAdmin("Odinstalowanie agenta"); err != nil {
		return err
	}
	if err := deleteService(); err != nil && !errors.Is(err, errNotInstalled) {
		return err
	}
	fmt.Println("Usługa SiemAgent usunięta.")
	_ = logging.RemoveEventSource(serviceName)

	if err := removeFromSystemPath(installDir); err != nil {
		fmt.Println("uwaga: PATH:", err)
	}

	if purge {
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Println("uwaga: nie usunięto danych:", err)
		} else {
			fmt.Println("Usunięto dane, konfigurację i certyfikaty:", dataDir)
		}
		// Klucze rejestru usuwa się od najgłębszych (DeleteKey nie usuwa podkluczy).
		for _, k := range listInstances() {
			_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent\Instances\`+k)
		}
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent\Instances`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\SiemAgent`)
	} else {
		fmt.Println("Dane i konfiguracja pozostały w", dataDir, "(usuń je opcją -purge).")
	}

	// Usunięcie folderu programu. Jeśli polecenie działa z tego folderu,
	// plik jest w użyciu – usuwamy go chwilę po zakończeniu procesu.
	exe, _ := os.Executable()
	if strings.HasPrefix(strings.ToLower(exe), strings.ToLower(installDir)) {
		cmd := exec.Command("cmd.exe", "/C", `ping -n 4 127.0.0.1 >NUL & rmdir /S /Q "`+installDir+`"`)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
			CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS}
		if err := cmd.Start(); err != nil {
			fmt.Println("uwaga: usuń ręcznie folder", installDir)
		}
	} else if err := os.RemoveAll(installDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Println("uwaga: nie usunięto folderu programu:", err)
	}
	fmt.Println("Agent odinstalowany.")
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
	if err := requireAdmin("Zmiana adresu serwera"); err != nil {
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
		return fmt.Errorf("konfiguracja po zmianie byłaby niepoprawna: %w", err)
	}
	if err := os.Rename(cfgPath+".tmp", cfgPath); err != nil {
		return err
	}
	fmt.Println("Nowy adres serwera:", serverURL)
	if err := testConnection(cfgPath); err != nil {
		fmt.Println("UWAGA:", err)
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
			return errors.New("brak dostępu do konfiguracji – uruchom jako administrator")
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
		return fmt.Errorf("połączenie z %s nieudane: %w", cfg.Server.URL, err)
	}
	fmt.Printf("Połączenie z %s: OK (agent %s, %s)\n", cfg.Server.URL, agentID, time.Since(start).Round(time.Millisecond))
	return nil
}

func prompt(question string) (string, error) {
	fmt.Print(question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("nie podano adresu serwera (użyj: siem_agent install -server <adres>)")
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
	return fmt.Errorf("brak plików paczki instalacyjnej:\n  %s\n\n"+
		"Instalację uruchamia się z folderu paczki utworzonej dla tego komputera, np.:\n"+
		`  bin\siem-pki.exe package -id agt-pc01 -server 192.168.88.98`+"\n"+
		`  cd dist\agt-pc01`+"\n"+
		`  .\siem_agent.exe install`+"\n"+
		"(albo wskaż pliki opcjami -ca, -cert, -key). Folder %s nie zawiera paczki.",
		strings.Join(missing, "\n  "), srcDir)
}
