// Package timesync sprawdza usługę czasu Windows (W32Time) – bez niej zegar
// komputera rozjeżdża się, a czasy zdarzeń przestają być wiarygodne.
package timesync

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceState zwraca stan usługi W32Time: running, stopped, disabled,
// missing albo unknown.
func ServiceState() string {
	m, err := mgr.Connect()
	if err != nil {
		return "unknown"
	}
	defer m.Disconnect()
	s, err := m.OpenService("W32Time")
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "missing"
		}
		return "unknown"
	}
	defer s.Close()
	if c, err := s.Config(); err == nil && c.StartType == mgr.StartDisabled {
		return "disabled"
	}
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	if st.State == svc.Running {
		return "running"
	}
	return "stopped"
}
