//go:build windows

package heartbeat

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// osVersion zwraca np. „Windows 11 Enterprise LTSC 2024 24H2 (26100.4061)”.
func osVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	get := func(name string) string { v, _, _ := k.GetStringValue(name); return v }
	product, display, build := get("ProductName"), get("DisplayVersion"), get("CurrentBuildNumber")
	ubr, _, _ := k.GetIntegerValue("UBR")
	// Windows 11 nadal ma w rejestrze „Windows 10” – rozpoznajemy po numerze kompilacji.
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	s := strings.TrimSpace(product + " " + display)
	if build != "" {
		s += fmt.Sprintf(" (%s.%d)", build, ubr)
	}
	return s
}
