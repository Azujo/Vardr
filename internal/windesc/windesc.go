// SPDX-License-Identifier: AGPL-3.0-or-later

// Package windesc zawiera krótkie opisy (po polsku i po angielsku)
// najważniejszych zdarzeń Windows (Event ID) – do raportów czytelnych dla
// osób spoza IT, np. w czytniku eksportu archiwum dla audytora. Lista
// obejmuje zdarzenia z profilu zbierania (roadmapa, załącznik B) i typowe
// zdarzenia systemowe.
package windesc

import "strings"

// Attention to kategorie zdarzeń wymagających uwagi w raporcie (kody;
// nazwa w języku raportu – AttentionLabel).
const (
	AttentionNone     = ""
	AttentionSecurity = "security" // zmiany kont, grup, polityk, czyszczenie dziennika
	AttentionLogon    = "logon"    // nieudane logowania, blokady
	AttentionSystem   = "system"   // nowe usługi, zadania, sterowniki
)

var attentionLabels = map[string][2]string{
	AttentionSecurity: {"bezpieczeństwo", "security"},
	AttentionLogon:    {"logowanie", "logon"},
	AttentionSystem:   {"system i usługi", "system and services"},
}

// AttentionLabel zwraca nazwę kategorii w języku lang (pl, en).
func AttentionLabel(cat, lang string) string { return pick(lang, attentionLabels[cat]) }

func pick(lang string, t [2]string) string {
	if lang == "en" {
		return t[1]
	}
	return t[0]
}

type entry struct {
	text      [2]string // pl, en
	attention string
}

var events = map[uint32]entry{
	// Logowanie i uwierzytelnianie
	4624: {[2]string{"Udane logowanie", "Successful logon"}, ""},
	4625: {[2]string{"Nieudane logowanie", "Failed logon"}, AttentionLogon},
	4634: {[2]string{"Wylogowanie", "Logoff"}, ""},
	4647: {[2]string{"Wylogowanie zainicjowane przez użytkownika", "User-initiated logoff"}, ""},
	4648: {[2]string{"Logowanie z jawnie podanymi poświadczeniami", "Logon with explicit credentials"}, ""},
	4672: {[2]string{"Przydzielenie uprawnień specjalnych przy logowaniu", "Special privileges assigned to a new logon"}, ""},
	4740: {[2]string{"Zablokowanie konta", "Account locked out"}, AttentionLogon},
	4767: {[2]string{"Odblokowanie konta", "Account unlocked"}, AttentionSecurity},
	4768: {[2]string{"Żądanie biletu Kerberos (TGT)", "Kerberos ticket (TGT) requested"}, ""},
	4769: {[2]string{"Żądanie biletu usługi Kerberos", "Kerberos service ticket requested"}, ""},
	4771: {[2]string{"Nieudane wstępne uwierzytelnienie Kerberos", "Kerberos pre-authentication failed"}, AttentionLogon},
	4776: {[2]string{"Weryfikacja poświadczeń (NTLM)", "Credential validation (NTLM)"}, ""},
	4778: {[2]string{"Ponowne połączenie sesji (RDP)", "Session reconnected (RDP)"}, ""},
	4779: {[2]string{"Rozłączenie sesji (RDP)", "Session disconnected (RDP)"}, ""},
	// Konta i grupy
	4720: {[2]string{"Utworzenie konta użytkownika", "User account created"}, AttentionSecurity},
	4722: {[2]string{"Włączenie konta użytkownika", "User account enabled"}, AttentionSecurity},
	4723: {[2]string{"Próba zmiany hasła", "Password change attempt"}, AttentionSecurity},
	4724: {[2]string{"Reset hasła konta", "Account password reset"}, AttentionSecurity},
	4725: {[2]string{"Wyłączenie konta użytkownika", "User account disabled"}, AttentionSecurity},
	4726: {[2]string{"Usunięcie konta użytkownika", "User account deleted"}, AttentionSecurity},
	4738: {[2]string{"Zmiana konta użytkownika", "User account changed"}, AttentionSecurity},
	4781: {[2]string{"Zmiana nazwy konta", "Account name changed"}, AttentionSecurity},
	4727: {[2]string{"Utworzenie globalnej grupy zabezpieczeń", "Security-enabled global group created"}, AttentionSecurity},
	4728: {[2]string{"Dodanie członka do globalnej grupy zabezpieczeń", "Member added to a security-enabled global group"}, AttentionSecurity},
	4729: {[2]string{"Usunięcie członka z globalnej grupy zabezpieczeń", "Member removed from a security-enabled global group"}, AttentionSecurity},
	4731: {[2]string{"Utworzenie lokalnej grupy zabezpieczeń", "Security-enabled local group created"}, AttentionSecurity},
	4732: {[2]string{"Dodanie członka do lokalnej grupy zabezpieczeń", "Member added to a security-enabled local group"}, AttentionSecurity},
	4733: {[2]string{"Usunięcie członka z lokalnej grupy zabezpieczeń", "Member removed from a security-enabled local group"}, AttentionSecurity},
	4735: {[2]string{"Zmiana lokalnej grupy zabezpieczeń", "Security-enabled local group changed"}, AttentionSecurity},
	4737: {[2]string{"Zmiana globalnej grupy zabezpieczeń", "Security-enabled global group changed"}, AttentionSecurity},
	4754: {[2]string{"Utworzenie uniwersalnej grupy zabezpieczeń", "Security-enabled universal group created"}, AttentionSecurity},
	4755: {[2]string{"Zmiana uniwersalnej grupy zabezpieczeń", "Security-enabled universal group changed"}, AttentionSecurity},
	4756: {[2]string{"Dodanie członka do uniwersalnej grupy zabezpieczeń", "Member added to a security-enabled universal group"}, AttentionSecurity},
	4757: {[2]string{"Usunięcie członka z uniwersalnej grupy zabezpieczeń", "Member removed from a security-enabled universal group"}, AttentionSecurity},
	// Polityki i dziennik
	1102: {[2]string{"Wyczyszczenie dziennika zabezpieczeń", "Security log cleared"}, AttentionSecurity},
	104:  {[2]string{"Wyczyszczenie dziennika zdarzeń", "Event log cleared"}, AttentionSecurity},
	4719: {[2]string{"Zmiana zasad inspekcji systemu", "System audit policy changed"}, AttentionSecurity},
	4739: {[2]string{"Zmiana zasad domeny", "Domain policy changed"}, AttentionSecurity},
	4713: {[2]string{"Zmiana zasad Kerberos", "Kerberos policy changed"}, AttentionSecurity},
	4706: {[2]string{"Utworzenie relacji zaufania z domeną", "Trust to a domain created"}, AttentionSecurity},
	4707: {[2]string{"Usunięcie relacji zaufania z domeną", "Trust to a domain removed"}, AttentionSecurity},
	4794: {[2]string{"Próba ustawienia hasła trybu przywracania usług katalogowych", "Attempt to set the Directory Services Restore Mode password"}, AttentionSecurity},
	5136: {[2]string{"Zmiana obiektu usługi katalogowej (AD)", "Directory service object modified (AD)"}, ""},
	5137: {[2]string{"Utworzenie obiektu usługi katalogowej (AD)", "Directory service object created (AD)"}, ""},
	5141: {[2]string{"Usunięcie obiektu usługi katalogowej (AD)", "Directory service object deleted (AD)"}, AttentionSecurity},
	// Procesy, usługi, zadania
	4688: {[2]string{"Utworzenie procesu", "Process created"}, ""},
	4689: {[2]string{"Zakończenie procesu", "Process exited"}, ""},
	4697: {[2]string{"Instalacja usługi w systemie", "Service installed in the system"}, AttentionSystem},
	4698: {[2]string{"Utworzenie zadania zaplanowanego", "Scheduled task created"}, AttentionSystem},
	4699: {[2]string{"Usunięcie zadania zaplanowanego", "Scheduled task deleted"}, AttentionSystem},
	4700: {[2]string{"Włączenie zadania zaplanowanego", "Scheduled task enabled"}, AttentionSystem},
	4702: {[2]string{"Zmiana zadania zaplanowanego", "Scheduled task updated"}, AttentionSystem},
	7045: {[2]string{"Instalacja nowej usługi", "New service installed"}, AttentionSystem},
	7040: {[2]string{"Zmiana typu uruchamiania usługi", "Service start type changed"}, ""},
	7036: {[2]string{"Zmiana stanu usługi", "Service state changed"}, ""},
	7034: {[2]string{"Nieoczekiwane zakończenie usługi", "Service terminated unexpectedly"}, ""},
	// Dostęp do zasobów i sieć
	4663: {[2]string{"Próba dostępu do obiektu", "Attempt to access an object"}, ""},
	5140: {[2]string{"Dostęp do udziału sieciowego", "Network share accessed"}, ""},
	5145: {[2]string{"Sprawdzenie dostępu do pliku w udziale sieciowym", "Network share file access check"}, ""},
	5156: {[2]string{"Zezwolenie na połączenie (zapora Windows)", "Connection allowed (Windows Firewall)"}, ""},
	5157: {[2]string{"Zablokowanie połączenia (zapora Windows)", "Connection blocked (Windows Firewall)"}, ""},
	// PowerShell, system, aplikacje
	4103: {[2]string{"Wykonanie potoku PowerShell", "PowerShell pipeline execution"}, ""},
	4104: {[2]string{"Wykonanie bloku skryptu PowerShell", "PowerShell script block execution"}, ""},
	1074: {[2]string{"Zamknięcie lub ponowne uruchomienie systemu", "System shutdown or restart"}, ""},
	6005: {[2]string{"Uruchomienie dziennika zdarzeń (start systemu)", "Event log started (system start)"}, ""},
	6006: {[2]string{"Zatrzymanie dziennika zdarzeń (zamknięcie systemu)", "Event log stopped (system shutdown)"}, ""},
	6008: {[2]string{"Nieoczekiwane zamknięcie systemu", "Unexpected system shutdown"}, ""},
	1000: {[2]string{"Awaria aplikacji", "Application crash"}, ""},
	1001: {[2]string{"Raport o błędzie (Windows Error Reporting)", "Error report (Windows Error Reporting)"}, ""},
	4616: {[2]string{"Zmiana czasu systemowego", "System time changed"}, AttentionSecurity},
}

// Describe zwraca opis zdarzenia w języku lang (pl, en) albo "" dla
// nieznanego kodu.
func Describe(code uint32, lang string) string {
	e, ok := events[code]
	if !ok {
		return ""
	}
	return pick(lang, e.text)
}

// Attention zwraca kategorię „wymaga uwagi” albo "".
func Attention(code uint32) string { return events[code].attention }

// logonTypes opisuje pole LogonType zdarzeń logowania (4624, 4625, 4634…).
var logonTypes = map[string][2]string{
	"2":  {"interaktywne – przy komputerze", "interactive – at the computer"},
	"3":  {"sieciowe – np. udział, zasób", "network – e.g. a share, a resource"},
	"4":  {"wsadowe – zadanie zaplanowane", "batch – scheduled task"},
	"5":  {"usługa", "service"},
	"7":  {"odblokowanie ekranu", "screen unlock"},
	"8":  {"sieciowe z hasłem jawnym", "network with a cleartext password"},
	"9":  {"nowe poświadczenia (runas /netonly)", "new credentials (runas /netonly)"},
	"10": {"zdalny pulpit (RDP)", "remote desktop (RDP)"},
	"11": {"z zapamiętanych poświadczeń, bez kontrolera domeny", "cached credentials, without a domain controller"},
	"12": {"zdalne z zapamiętanych poświadczeń", "remote with cached credentials"},
	"13": {"odblokowanie z zapamiętanych poświadczeń", "unlock with cached credentials"},
}

// FieldHint zwraca objaśnienie wartości pola zdarzenia albo "".
func FieldHint(name, value, lang string) string {
	if name == "LogonType" {
		if t, ok := logonTypes[value]; ok {
			return pick(lang, t)
		}
	}
	return ""
}

// detailFields: pola opisujące „czego dotyczy” zdarzenie, w kolejności ważności.
var detailFields = [][]string{
	{"ServiceName", "ImagePath"},           // 7045, 4697 – usługa
	{"TaskName"},                           // 4698–4702 – zadanie zaplanowane
	{"MemberName", "TargetUserName"},       // 4728/4732/4756 – kto do jakiej grupy
	{"TargetUserName", "TargetDomainName"}, // konta, logowania
	{"SubjectUserName"},                    // 1102, 4719 – kto wykonał
}

// Detail zwraca krótki opis przedmiotu zdarzenia z jego danych (np. nazwa
// i ścieżka usługi, konto i grupa) albo "".
func Detail(data map[string]string) string {
	for _, group := range detailFields {
		var parts []string
		for _, f := range group {
			if v := data[f]; v != "" && v != "-" {
				parts = append(parts, v)
			}
		}
		if len(parts) > 0 && data[group[0]] != "" {
			return strings.Join(parts, " | ")
		}
	}
	return ""
}
