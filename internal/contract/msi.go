package contract

import "strings"

// Instalator MSI agenta ma właściwości SERVER i TOKEN z wypełniaczami stałej
// długości (deploy/lab/msi/agent.wxs). Panel przy pobraniu instalatora
// podmienia je w pliku na adres serwera i token, dopełnione spacjami do tej
// samej długości (internal/msipatch) – jeden plik MSI instaluje i rejestruje
// agenta bez parametrów msiexec, a na komputerze z agentem go aktualizuje.
const (
	MSIServerPlaceholder = "HEIMDALL_MSI_SERVER_============================================================================================================"
	MSITokenPlaceholder  = "HEIMDALL_MSI_TOKEN_============================================="
)

// MSIValue zwraca wartość właściwości MSI bez dopełnienia; pusty napis,
// gdy to niepodmieniony wypełniacz (bazowy instalator – aktualizacja albo
// instalacja z parametrami SERVER= TOKEN= w msiexec).
func MSIValue(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "HEIMDALL_MSI_") {
		return ""
	}
	return v
}
