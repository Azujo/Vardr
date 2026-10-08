//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"siem/agent/internal/config"
	"siem/agent/internal/logging"
	"siem/agent/internal/shipper"
)

// Instalator MSI (heimdall-agent.msi) kopiuje siem_agent.exe i ca.crt do
// %ProgramFiles%\SiemAgent, a potem – jako SYSTEM – uruchamia:
//
//	siem_agent msi-install -server <SERVER> -token <TOKEN>   po instalacji plików
//	siem_agent msi-uninstall                                przed usunięciem plików
//
// Aktualizacja nowszym MSI najpierw usuwa starą wersję (msi-uninstall
// zostawia dane i certyfikaty), a msi-install nowej wersji widzi istniejącą
// rejestrację i tylko ponownie rejestruje usługę – bez nowego tokenu.
// Przebieg trafia do %ProgramData%\SiemAgent\msi.log (okno MSI nie pokazuje
// wyjścia programu).

func msiLog() (io.Writer, func()) {
	_ = os.MkdirAll(dataDir, 0o700)
	f, err := os.OpenFile(filepath.Join(dataDir, "msi.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return os.Stdout, func() {}
	}
	fmt.Fprintf(f, "\n== %s siem_agent %s %v\n", time.Now().Format(time.RFC3339), version, os.Args[1])
	return f, func() { f.Close() }
}

// redirect kieruje wyjście poleceń instalacji do pliku dziennika MSI.
func redirect(w io.Writer) func() {
	f, ok := w.(*os.File)
	if !ok {
		return func() {}
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	return func() { os.Stdout, os.Stderr = oldOut, oldErr }
}

// enrolledAlready: agent ma już konfigurację i ważny certyfikat (aktualizacja
// albo naprawa instalacji).
func enrolledAlready() bool {
	certDir := filepath.Join(dataDir, "certs")
	if _, err := config.Load(installCfg); err != nil {
		return false
	}
	_, _, err := shipper.NewTLSClient(filepath.Join(certDir, "ca.crt"), filepath.Join(certDir, "agent.crt"),
		filepath.Join(certDir, "agent.key"), 5*time.Second)
	return err == nil
}

func msiInstall(server, token string) error {
	logw, closeLog := msiLog()
	defer closeLog()
	defer redirect(logw)()

	if enrolledAlready() {
		fmt.Println("Agent już zarejestrowany – aktualizacja/naprawa: rejestracja usługi z istniejącą konfiguracją.")
		if _, err := queryService(); err != nil {
			if err := logging.InstallEventSource(serviceName); err != nil {
				fmt.Println("uwaga: źródło w dzienniku zdarzeń:", err)
			}
			if err := registerService(installExe, installCfg); err != nil {
				return err
			}
		}
		if err := addToSystemPath(installDir); err != nil {
			fmt.Println("uwaga: PATH:", err)
		}
		if err := restartOrStart(); err != nil {
			return fmt.Errorf("usługa nie wystartowała: %w", err)
		}
		fmt.Println("Usługa SiemAgent działa.")
		return nil
	}
	if token == "" && !fileExists(filepath.Join(installDir, "token.txt")) {
		return errors.New("brak tokenu rejestracyjnego – podaj TOKEN=… (panel → Bifröst) w poleceniu msiexec")
	}
	if server == "" {
		return errors.New("brak adresu serwera – podaj SERVER=… w poleceniu msiexec")
	}
	// Pozostałość po instalacji bez MSI (siem_agent install): usługa istnieje,
	// ale konfiguracji brak – usuwamy usługę, żeby instalacja przeszła.
	if _, err := queryService(); err == nil {
		_ = deleteService()
	}
	return install(installOptions{server: server, token: token, ca: filepath.Join(installDir, "ca.crt"), startAt: "now"})
}

func restartOrStart() error {
	return withService(func(s *mgr.Service) error {
		if st, _ := s.Query(); st.State != svc.Stopped {
			if _, err := s.Control(svc.Stop); err == nil {
				_ = waitState(s, svc.Stopped, 30*time.Second)
			}
		}
		if err := s.Start(); err != nil {
			return err
		}
		return waitState(s, svc.Running, 15*time.Second)
	})
}

// msiUninstall usuwa usługę, źródło zdarzeń i wpis w PATH; dane,
// konfiguracja i certyfikaty zostają (pliki programu usuwa MSI).
func msiUninstall() error {
	logw, closeLog := msiLog()
	defer closeLog()
	defer redirect(logw)()
	if err := deleteService(); err != nil && !errors.Is(err, errNotInstalled) {
		return err
	}
	_ = logging.RemoveEventSource(serviceName)
	if err := removeFromSystemPath(installDir); err != nil {
		fmt.Println("uwaga: PATH:", err)
	}
	fmt.Println("Usługa usunięta; dane i certyfikaty zostały w", dataDir)
	return nil
}
