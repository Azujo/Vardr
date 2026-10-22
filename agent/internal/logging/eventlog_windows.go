// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package logging

import (
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

// InstallEventSource rejestruje źródło zdarzeń w dzienniku Application
// (wymaga administratora; wywoływane przy instalacji usługi).
func InstallEventSource(name string) error {
	err := eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil && isAlreadyExists(err) {
		return nil
	}
	return err
}

// RemoveEventSource usuwa rejestrację źródła zdarzeń.
func RemoveEventSource(name string) error { return eventlog.Remove(name) }

// OpenEventSink otwiera dziennik do zapisu dla zarejestrowanego źródła.
func OpenEventSink(name string) (*eventlog.Log, error) { return eventlog.Open(name) }

func isAlreadyExists(err error) bool {
	// InstallAsEventCreate zwraca błąd z komunikatem "... registry key already exists".
	return err != nil && strings.Contains(err.Error(), "already exists")
}
