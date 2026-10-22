// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package guard

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	// OpenSDDL: domyślne uprawnienia usługi Windows (jak po utworzeniu).
	OpenSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
	// ProtectedSDDL: administrator sprawdzi stan, uruchomi usługę i wyśle
	// polecenie agenta (restart – kod 128), ale jej nie zatrzyma, nie
	// wstrzyma, nie przekonfiguruje ani nie usunie. Zostaje mu WRITE_DAC
	// (polecenia z tokenem otwierają nim usługę) – to granica ochrony: zmianę
	// uprawnień agent wykrywa, zgłasza i cofa. Zwykli użytkownicy nie wysyłają
	// poleceń agenta.
	ProtectedSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWD;;;BA)(A;;CCLCSWLORC;;;IU)(A;;CCLCSWLORC;;;SU)"

	// Stany uprawnień usługi.
	StateProtected = "protected"
	StateOpen      = "open"
)

// ControlRestart: polecenie użytkownika usługi – ponowne uruchomienie agenta
// w procesie usługi (z nową konfiguracją), bez prawa do zatrzymania.
const ControlRestart = 128

func canonical(sddl string) string {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return sddl
	}
	s := sd.String()
	if i := strings.Index(s, "D:"); i >= 0 {
		s = s[i:]
	}
	if i := strings.Index(s, "S:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func openService(name string, access uint32) (windows.Handle, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, nil, err
	}
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenService(scm, n, access)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return 0, nil, err
	}
	return h, func() { windows.CloseServiceHandle(h); windows.CloseServiceHandle(scm) }, nil
}

// ServiceACL zwraca stan uprawnień usługi: protected, open albo SDDL innych
// uprawnień (zmienione z zewnątrz).
func ServiceACL(name string) (string, error) {
	h, done, err := openService(name, windows.READ_CONTROL)
	if err != nil {
		return "", err
	}
	defer done()
	sd, err := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	got := canonical(sd.String())
	switch got {
	case canonical(ProtectedSDDL):
		return StateProtected, nil
	case canonical(OpenSDDL):
		return StateOpen, nil
	}
	return got, nil
}

// SetServiceACL ustawia uprawnienia usługi (protected albo open).
func SetServiceACL(name, state string) error {
	sddl := OpenSDDL
	if state == StateProtected {
		sddl = ProtectedSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	h, done, err := openService(name, windows.WRITE_DAC|windows.READ_CONTROL)
	if err != nil {
		return err
	}
	defer done()
	return windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// ServiceConfig to pilnowana część konfiguracji usługi.
type ServiceConfig struct {
	StartType  uint32
	BinaryPath string
}

// ReadConfig odczytuje konfigurację usługi z menedżera usług.
func ReadConfig(name string) (ServiceConfig, error) {
	h, done, err := openService(name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return ServiceConfig{}, err
	}
	defer done()
	var need uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &need)
	if need == 0 {
		need = 1024
	}
	buf := make([]byte, need)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(h, cfg, need, &need); err != nil {
		return ServiceConfig{}, err
	}
	return ServiceConfig{StartType: cfg.StartType, BinaryPath: windows.UTF16PtrToString(cfg.BinaryPathName)}, nil
}

var startNames = map[uint32]string{windows.SERVICE_AUTO_START: "automatyczny", windows.SERVICE_DEMAND_START: "ręczny",
	windows.SERVICE_DISABLED: "wyłączony", windows.SERVICE_BOOT_START: "boot", windows.SERVICE_SYSTEM_START: "system"}

func startName(t uint32) string {
	if n, ok := startNames[t]; ok {
		return n
	}
	return fmt.Sprint(t)
}

// CheckConfig porównuje konfigurację usługi (w menedżerze usług i w rejestrze –
// zmiana w rejestrze działa dopiero po restarcie systemu) z oczekiwaną: typ
// automatyczny i program, który uruchomił agenta. fix=true przywraca.
// Zwraca opis zmian (pusty – bez zmian).
func CheckConfig(name string, want ServiceConfig, fix bool) ([]string, error) {
	var diffs []string
	cur, err := ReadConfig(name)
	if err != nil {
		return nil, err
	}
	scmWrong := false
	if cur.StartType != windows.SERVICE_AUTO_START {
		diffs = append(diffs, "typ uruchamiania: "+startName(cur.StartType))
		scmWrong = true
	}
	if !strings.EqualFold(cur.BinaryPath, want.BinaryPath) {
		diffs = append(diffs, "program usługi: "+cur.BinaryPath)
		scmWrong = true
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE|registry.SET_VALUE)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("Start"); err == nil && v != windows.SERVICE_AUTO_START && !scmWrong {
			diffs = append(diffs, "typ uruchamiania w rejestrze: "+startName(uint32(v)))
			if fix {
				_ = k.SetDWordValue("Start", windows.SERVICE_AUTO_START)
			}
		}
		if v, _, err := k.GetStringValue("ImagePath"); err == nil && !strings.EqualFold(v, want.BinaryPath) && !scmWrong {
			diffs = append(diffs, "program usługi w rejestrze: "+v)
			if fix {
				_ = k.SetExpandStringValue("ImagePath", want.BinaryPath)
			}
		}
	}
	if fix && scmWrong {
		h, done, err := openService(name, windows.SERVICE_CHANGE_CONFIG)
		if err != nil {
			return diffs, err
		}
		defer done()
		path, _ := windows.UTF16PtrFromString(want.BinaryPath)
		if err := windows.ChangeServiceConfig(h, windows.SERVICE_NO_CHANGE, windows.SERVICE_AUTO_START, windows.SERVICE_NO_CHANGE,
			path, nil, nil, nil, nil, nil, nil); err != nil {
			return diffs, err
		}
	}
	return diffs, nil
}

// BootTime to chwila startu systemu.
func BootTime() time.Time {
	return time.Now().Add(-windows.DurationSinceBoot()).UTC().Truncate(time.Second)
}

// CurrentUser to konto, z którego działa polecenie (DOMENA\nazwa).
func CurrentUser() string {
	var size uint32 = 256
	buf := make([]uint16, size)
	if err := windows.GetUserNameEx(windows.NameSamCompatible, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
