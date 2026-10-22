// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"path/filepath"
	"regexp"
	"strconv"
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

// Konto TrustedInstaller (właściciel plików systemowych).
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// adminTrustees to konta, które mogą zapisywać pliki usługi bez ryzyka
// eskalacji uprawnień (i tak mają pełną kontrolę nad systemem).
var adminTrustees = map[string]bool{"SY": true, "BA": true, trustedInstaller: true}

// Bity praw pozwalających zmienić plik/folder lub jego uprawnienia.
const writeMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | // zapis, dopisywanie, EA, usuwanie dzieci, atrybuty
	0x10000 | 0x40000 | 0x80000 | // DELETE, WRITE_DAC, WRITE_OWNER
	0x10000000 | 0x40000000 // GENERIC_ALL, GENERIC_WRITE

// Dwuliterowe skróty praw SDDL oznaczające możliwość zapisu.
var writeCodes = map[string]bool{"FA": true, "FW": true, "GA": true, "GW": true, "WD": true, "WO": true,
	"SD": true, "WP": true, "CC": true, "DC": true}

var (
	sddlOwner = regexp.MustCompile(`^O:([^:]+?)(?:G:|D:|S:|$)`)
	sddlACE   = regexp.MustCompile(`\(([A-Z]+);([A-Z]*);([^;]*);[^;]*;[^;]*;([^)]+)\)`)
)

// writeRisks analizuje SDDL i zwraca konta spoza administratorów, które
// mogą zmodyfikować obiekt (prawo zapisu albo bycie właścicielem).
func writeRisks(sddl string) []string {
	var risks []string
	if m := sddlOwner.FindStringSubmatch(sddl); m != nil && !adminTrustees[m[1]] {
		risks = append(risks, m[1]+" (właściciel)")
	}
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return append(risks, "brak listy DACL")
	}
	for _, m := range sddlACE.FindAllStringSubmatch(sddl[i:], -1) {
		typ, flags, rights, who := m[1], m[2], m[3], m[4]
		if typ != "A" || strings.Contains(flags, "IO") || adminTrustees[who] {
			continue // nie-zezwalające, tylko-dziedziczone lub administratorzy
		}
		if rightsAllowWrite(rights) {
			risks = append(risks, who)
		}
	}
	return risks
}

func rightsAllowWrite(rights string) bool {
	if strings.HasPrefix(rights, "0x") {
		v, err := strconv.ParseUint(rights[2:], 16, 32)
		return err != nil || v&writeMask != 0 // nieczytelna maska = traktuj jako ryzyko
	}
	for j := 0; j+2 <= len(rights); j += 2 {
		if writeCodes[rights[j:j+2]] {
			return true
		}
	}
	return false
}

// WritableByNonAdmins sprawdza, czy plik lub folder może zmodyfikować ktoś
// spoza SYSTEM / Administratorów / TrustedInstaller. Dla pliku usługi
// działającej jako SYSTEM oznacza to możliwość eskalacji uprawnień
// (podmiana pliku wykonywalnego).
func WritableByNonAdmins(path string) (bool, string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true, "", err
	}
	risks := writeRisks(sd.String())
	if len(risks) == 0 {
		return false, "", nil
	}
	names := make([]string, len(risks))
	for i, r := range risks {
		sid, suffix, _ := strings.Cut(r, " ")
		names[i] = strings.TrimSpace(accountName(sid) + " " + suffix)
	}
	return true, strings.Join(names, ", "), nil
}

// ServiceBinarySafe sprawdza plik wykonywalny usługi i jego folder.
func ServiceBinarySafe(exe string) (bool, string) {
	for _, p := range []string{exe, filepath.Dir(exe)} {
		w, who, err := WritableByNonAdmins(p)
		if err != nil {
			return false, fmt.Sprintf("%s: nie można sprawdzić uprawnień: %v", p, err)
		}
		if w {
			return false, fmt.Sprintf("%s: zapis mogą wykonać: %s", p, who)
		}
	}
	return true, ""
}
