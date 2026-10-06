//go:build windows

// Package secure ogranicza dostęp do plików agenta (klucz prywatny, stan,
// logi, kwarantanna) do kont SYSTEM i Administratorzy.
//
// Uprawnienia w stylu Unix (0600) przekazywane do os.WriteFile nie mają na
// Windows wpływu na ACL – pliki dziedziczą uprawnienia folderu nadrzędnego,
// a w C:\ProgramData zwykli użytkownicy mają prawo odczytu.
package secure

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	// Chroniona lista DACL (bez dziedziczenia od rodzica): pełny dostęp tylko
	// SYSTEM (SY) i Administratorzy (BA); dziedziczona przez pliki i podfoldery.
	dirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// RestrictDir ustawia chronioną listę dostępu na katalogu. Windows propaguje
// ją na istniejące pliki i podkatalogi, które dziedziczą uprawnienia.
func RestrictDir(path string) error { return setDACL(path, dirSDDL) }

// RestrictFile ustawia chronioną listę dostępu na pojedynczym pliku.
func RestrictFile(path string) error { return setDACL(path, fileSDDL) }

func setDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("ustawienie uprawnień %s: %w", path, err)
	}
	return nil
}

// aceTrustee wyciąga typ ACE i konto z zapisu SDDL, np. (A;OICI;FA;;;SY).
var aceTrustee = regexp.MustCompile(`\(([A-Z]+);[^;]*;[^;]*;[^;]*;[^;]*;([^)]+)\)`)

// IsRestricted sprawdza, czy dostęp do ścieżki mają wyłącznie SYSTEM
// i Administratorzy. Zwraca opis kont, które mają dodatkowy dostęp.
func IsRestricted(path string) (bool, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, "", err
	}
	sddl := sd.String()
	i := strings.Index(sddl, "D:")
	if i < 0 || strings.Contains(sddl, "NO_ACCESS_CONTROL") {
		return false, "brak listy DACL (dostęp dla wszystkich)", nil
	}
	var extra []string
	for _, m := range aceTrustee.FindAllStringSubmatch(sddl[i:], -1) {
		typ, who := m[1], m[2]
		if typ != "A" && typ != "OA" { // ACE odmowy nie poszerzają dostępu
			continue
		}
		if who != "SY" && who != "BA" {
			extra = append(extra, accountName(who))
		}
	}
	if len(extra) > 0 {
		return false, "dostęp mają również: " + strings.Join(extra, ", "), nil
	}
	return true, "", nil
}

func accountName(sddlTrustee string) string {
	aliases := map[string]string{
		"BU": "Użytkownicy", "AU": "Uwierzytelnieni użytkownicy", "WD": "Wszyscy",
		"IU": "Interaktywni", "CO": "Właściciel twórca", "OW": "Prawa właściciela",
	}
	if n, ok := aliases[sddlTrustee]; ok {
		return n
	}
	sid, err := windows.StringToSid(sddlTrustee)
	if err != nil {
		return sddlTrustee
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sddlTrustee
	}
	return domain + `\` + account
}

// IsPrivileged zwraca true, gdy proces działa jako SYSTEM lub z podniesionymi
// uprawnieniami administratora – tylko wtedy może bezpiecznie zawęzić ACL
// bez odcięcia samego siebie.
func IsPrivileged() bool {
	tok := windows.GetCurrentProcessToken()
	if tok.IsElevated() {
		return true
	}
	user, err := tok.GetTokenUser()
	if err != nil {
		return false
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return err == nil && user.User.Sid.Equals(system)
}
