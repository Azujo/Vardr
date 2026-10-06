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
