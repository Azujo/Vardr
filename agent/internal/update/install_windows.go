// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// Pakiet: instalator MSI; dziennik msiexec.
const (
	pkgSuffix = ".msi"
	logPrefix = "msiexec-"
)

// startInstaller uruchamia msiexec bez okna, w osobnej grupie procesów:
// instalator zatrzymuje usługę agenta (a więc i ten proces) i musi działać
// dalej. Agent działa jako SYSTEM, więc instalacja nie pyta o uprawnienia.
func startInstaller(msi, logPath string) (func() error, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	cmd := exec.Command(exe, "/i", msi, "/qn", "/norestart", "/l*v", logPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd.Wait, nil
}
