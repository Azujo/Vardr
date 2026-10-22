// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package secure

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// restoreForCleanup przywraca pełny dostęp bieżącemu użytkownikowi (jako
// właściciel zawsze możemy zmienić DACL), żeby t.TempDir dało się usunąć.
func restoreForCleanup(t *testing.T, dir string) {
	t.Cleanup(func() {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Log(err)
			return
		}
		if err := setDACL(dir, "D:(A;OICI;FA;;;"+user.User.Sid.String()+")"); err != nil {
			t.Log(err)
		}
	})
}

func TestRestrictDirBlocksOtherUsers(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(key, []byte("tajny klucz"), 0o600); err != nil {
		t.Fatal(err)
	}

	before, _, err := IsRestricted(key)
	if err != nil {
		t.Fatal(err)
	}
	if before {
		t.Fatal("plik w katalogu tymczasowym nie powinien być domyślnie zawężony")
	}

	restoreForCleanup(t, dir)
	if err := RestrictDir(dir); err != nil {
		t.Fatal(err)
	}

	if IsPrivileged() {
		t.Skip("test uruchomiony jako administrator – nie da się sprawdzić odmowy odczytu")
	}
	// Bieżący (nieuprzywilejowany) użytkownik nie może już odczytać klucza –
	// uprawnienia katalogu zostały rozpropagowane na istniejący plik.
	if _, err := os.ReadFile(key); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("odczyt klucza powinien być zabroniony, jest: %v", err)
	}
}

func TestRestrictFileAndIsRestricted(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.key")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	restoreForCleanup(t, dir)
	t.Cleanup(func() { _ = setDACL(p, "D:AI") }) // przywróć dziedziczenie z katalogu

	if err := RestrictFile(p); err != nil {
		t.Fatal(err)
	}
	ok, why, err := IsRestricted(p)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("plik powinien być zawężony: %s", why)
	}
}

func TestWriteRisksOnRealSDDL(t *testing.T) {
	const ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	const user = "S-1-5-21-807202919-2637959309-2781131931-1001"
	cases := []struct {
		name  string
		sddl  string
		risky bool
	}{
		{"Program Files", "O:" + ti + "G:" + ti + "D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;" + ti + ")(A;;FA;;;" + ti + ")(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)", false},
		{"svchost.exe", "O:" + ti + "G:" + ti + "D:P(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;" + ti + ")", false},
		{"folder projektu (właściciel i pełny dostęp użytkownika)", "O:" + user + "G:" + user + "D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;" + user + ")", true},
		{"Użytkownicy z prawem modyfikacji", "O:BAD:(A;;0x1301bf;;;BU)", true},
		{"Wszyscy z GENERIC_WRITE", "O:SYD:(A;;GW;;;WD)", true},
		{"odmowa nie jest ryzykiem", "O:BAD:(D;;FA;;;BU)(A;;FA;;;SY)", false},
	}
	for _, c := range cases {
		if got := writeRisks(c.sddl); (len(got) > 0) != c.risky {
			t.Errorf("%s: ryzyka %q, oczekiwano ryzyka=%v", c.name, got, c.risky)
		}
	}
}

func TestServiceBinarySafeOnThisMachine(t *testing.T) {
	if ok, why := ServiceBinarySafe(`C:\Windows\System32\svchost.exe`); !ok {
		t.Errorf("plik systemowy powinien być bezpieczny: %s", why)
	}
	exe := filepath.Join(t.TempDir(), "agent.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ServiceBinarySafe(exe); ok {
		t.Error("plik w katalogu tymczasowym użytkownika nie może być uznany za bezpieczny")
	}
}
