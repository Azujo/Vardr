// Package windesc zawiera krótkie polskie opisy najważniejszych zdarzeń
// Windows (Event ID) – do raportów czytelnych dla osób spoza IT, np. w czytniku
// eksportu archiwum dla audytora. Lista obejmuje zdarzenia z profilu
// zbierania (roadmapa, załącznik B) i typowe zdarzenia systemowe.
package windesc

import "strings"

// Attention to kategorie zdarzeń wymagających uwagi w raporcie.
const (
	AttentionNone     = ""
	AttentionSecurity = "bezpieczeństwo"  // zmiany kont, grup, polityk, czyszczenie dziennika
	AttentionLogon    = "logowanie"       // nieudane logowania, blokady
	AttentionSystem   = "system i usługi" // nowe usługi, zadania, sterowniki
)

type entry struct {
	text      string
	attention string
}

var events = map[uint32]entry{
	// Logowanie i uwierzytelnianie
	4624: {"Udane logowanie", ""},
	4625: {"Nieudane logowanie", AttentionLogon},
	4634: {"Wylogowanie", ""},
	4647: {"Wylogowanie zainicjowane przez użytkownika", ""},
	4648: {"Logowanie z jawnie podanymi poświadczeniami", ""},
	4672: {"Przydzielenie uprawnień specjalnych przy logowaniu", ""},
	4740: {"Zablokowanie konta", AttentionLogon},
	4767: {"Odblokowanie konta", AttentionSecurity},
	4768: {"Żądanie biletu Kerberos (TGT)", ""},
	4769: {"Żądanie biletu usługi Kerberos", ""},
	4771: {"Nieudane wstępne uwierzytelnienie Kerberos", AttentionLogon},
	4776: {"Weryfikacja poświadczeń (NTLM)", ""},
	4778: {"Ponowne połączenie sesji (RDP)", ""},
	4779: {"Rozłączenie sesji (RDP)", ""},
	// Konta i grupy
	4720: {"Utworzenie konta użytkownika", AttentionSecurity},
	4722: {"Włączenie konta użytkownika", AttentionSecurity},
	4723: {"Próba zmiany hasła", AttentionSecurity},
	4724: {"Reset hasła konta", AttentionSecurity},
	4725: {"Wyłączenie konta użytkownika", AttentionSecurity},
	4726: {"Usunięcie konta użytkownika", AttentionSecurity},
	4738: {"Zmiana konta użytkownika", AttentionSecurity},
	4781: {"Zmiana nazwy konta", AttentionSecurity},
	4727: {"Utworzenie globalnej grupy zabezpieczeń", AttentionSecurity},
	4728: {"Dodanie członka do globalnej grupy zabezpieczeń", AttentionSecurity},
	4729: {"Usunięcie członka z globalnej grupy zabezpieczeń", AttentionSecurity},
	4731: {"Utworzenie lokalnej grupy zabezpieczeń", AttentionSecurity},
	4732: {"Dodanie członka do lokalnej grupy zabezpieczeń", AttentionSecurity},
	4733: {"Usunięcie członka z lokalnej grupy zabezpieczeń", AttentionSecurity},
	4735: {"Zmiana lokalnej grupy zabezpieczeń", AttentionSecurity},
	4737: {"Zmiana globalnej grupy zabezpieczeń", AttentionSecurity},
	4754: {"Utworzenie uniwersalnej grupy zabezpieczeń", AttentionSecurity},
	4755: {"Zmiana uniwersalnej grupy zabezpieczeń", AttentionSecurity},
	4756: {"Dodanie członka do uniwersalnej grupy zabezpieczeń", AttentionSecurity},
	4757: {"Usunięcie członka z uniwersalnej grupy zabezpieczeń", AttentionSecurity},
	// Polityki i dziennik
	1102: {"Wyczyszczenie dziennika zabezpieczeń", AttentionSecurity},
	104:  {"Wyczyszczenie dziennika zdarzeń", AttentionSecurity},
	4719: {"Zmiana zasad inspekcji systemu", AttentionSecurity},
	4739: {"Zmiana zasad domeny", AttentionSecurity},
	4713: {"Zmiana zasad Kerberos", AttentionSecurity},
	4706: {"Utworzenie relacji zaufania z domeną", AttentionSecurity},
	4707: {"Usunięcie relacji zaufania z domeną", AttentionSecurity},
	4794: {"Próba ustawienia hasła trybu przywracania usług katalogowych", AttentionSecurity},
	5136: {"Zmiana obiektu usługi katalogowej (AD)", ""},
	5137: {"Utworzenie obiektu usługi katalogowej (AD)", ""},
	5141: {"Usunięcie obiektu usługi katalogowej (AD)", AttentionSecurity},
	// Procesy, usługi, zadania
	4688: {"Utworzenie procesu", ""},
	4689: {"Zakończenie procesu", ""},
	4697: {"Instalacja usługi w systemie", AttentionSystem},
	4698: {"Utworzenie zadania zaplanowanego", AttentionSystem},
	4699: {"Usunięcie zadania zaplanowanego", AttentionSystem},
	4700: {"Włączenie zadania zaplanowanego", AttentionSystem},
	4702: {"Zmiana zadania zaplanowanego", AttentionSystem},
	7045: {"Instalacja nowej usługi", AttentionSystem},
	7040: {"Zmiana typu uruchamiania usługi", ""},
	7036: {"Zmiana stanu usługi", ""},
	7034: {"Nieoczekiwane zakończenie usługi", ""},
	// Dostęp do zasobów i sieć
	4663: {"Próba dostępu do obiektu", ""},
	5140: {"Dostęp do udziału sieciowego", ""},
	5145: {"Sprawdzenie dostępu do pliku w udziale sieciowym", ""},
	5156: {"Zezwolenie na połączenie (zapora Windows)", ""},
	5157: {"Zablokowanie połączenia (zapora Windows)", ""},
	// PowerShell, system, aplikacje
	4103: {"Wykonanie potoku PowerShell", ""},
	4104: {"Wykonanie bloku skryptu PowerShell", ""},
	1074: {"Zamknięcie lub ponowne uruchomienie systemu", ""},
	6005: {"Uruchomienie dziennika zdarzeń (start systemu)", ""},
	6006: {"Zatrzymanie dziennika zdarzeń (zamknięcie systemu)", ""},
	6008: {"Nieoczekiwane zamknięcie systemu", ""},
	1000: {"Awaria aplikacji", ""},
	1001: {"Raport o błędzie (Windows Error Reporting)", ""},
	4616: {"Zmiana czasu systemowego", AttentionSecurity},
}

// Describe zwraca polski opis zdarzenia albo "" dla nieznanego kodu.
func Describe(code uint32) string { return events[code].text }

// Attention zwraca kategorię „wymaga uwagi” albo "".
func Attention(code uint32) string { return events[code].attention }

// logonTypes opisuje pole LogonType zdarzeń logowania (4624, 4625, 4634…).
var logonTypes = map[string]string{
	"2":  "interaktywne – przy komputerze",
	"3":  "sieciowe – np. udział, zasób",
	"4":  "wsadowe – zadanie zaplanowane",
	"5":  "usługa",
	"7":  "odblokowanie ekranu",
	"8":  "sieciowe z hasłem jawnym",
	"9":  "nowe poświadczenia (runas /netonly)",
	"10": "zdalny pulpit (RDP)",
	"11": "z zapamiętanych poświadczeń, bez kontrolera domeny",
	"12": "zdalne z zapamiętanych poświadczeń",
	"13": "odblokowanie z zapamiętanych poświadczeń",
}

// FieldHint zwraca objaśnienie wartości pola zdarzenia albo "".
func FieldHint(name, value string) string {
	if name == "LogonType" {
		return logonTypes[value]
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
