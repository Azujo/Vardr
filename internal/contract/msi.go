package contract

import "strings"

// Instalator MSI agenta ma właściwości SERVER i TOKEN z wypełniaczami stałej
// długości (deploy/lab/msi/agent.wxs). Panel przy pobraniu instalatora
// podmienia je w pliku na adres serwera i token, dopełnione spacjami do tej
// samej długości (internal/msipatch) – jeden plik MSI instaluje i rejestruje
// agenta bez parametrów msiexec, a na komputerze z agentem go aktualizuje.
const (
	MSIServerPlaceholder = "VARDR_MSI_SERVER_==============================================================================================================="
	MSITokenPlaceholder  = "VARDR_MSI_TOKEN_================================================"
)

// MSIValue zwraca wartość właściwości MSI bez dopełnienia; pusty napis,
// gdy to niepodmieniony wypełniacz (bazowy instalator – aktualizacja albo
// instalacja z parametrami SERVER= TOKEN= w msiexec).
func MSIValue(v string) string {
	v = strings.TrimSpace(v)
	// HEIMDALL_MSI_: wypełniacze instalatorów sprzed zmiany nazwy na Vardr.
	if strings.HasPrefix(v, "VARDR_MSI_") || strings.HasPrefix(v, "HEIMDALL_MSI_") {
		return ""
	}
	return v
}
