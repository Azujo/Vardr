//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPackageReportsMissingFilesBeforeChanges(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
	if err := os.WriteFile(ca, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := checkPackage(dir, ca, cert, key)
	if err == nil {
		t.Fatal("oczekiwano błędu dla niekompletnej paczki")
	}
	msg := err.Error()
	for _, want := range []string{"agent.crt", "agent.key", "siem-pki.exe package", `.\siem_agent.exe install`} {
		if !strings.Contains(msg, want) {
			t.Errorf("brak %q w komunikacie:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "ca.crt\n") {
		t.Error("istniejący plik nie powinien być zgłaszany jako brakujący")
	}

	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkPackage(dir, ca, cert, key); err != nil {
		t.Fatalf("kompletna paczka: %v", err)
	}
}
