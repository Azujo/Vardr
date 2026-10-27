// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strings"
)

// Pomoc dla kreatora korelacji w panelu: pola zdarzenia pod nazwami, których
// używa reguła, i logsource pasujący do zbioru danych zdarzenia.

// wizardStd: pola wspólne (nazwy z Event.Get) pokazywane w kreatorze.
var wizardStd = []string{"EventID", "Channel", "event.dataset", "event.action", "event.outcome", "event.provider",
	"host.name", "user.name", "user.domain", "user.identity", "source.ip", "process.name", "process.command_line"}

// Flat zwraca pola zdarzenia pod nazwami, których może użyć reguła
// (niepuste; pola EventData pod własnymi nazwami, kanał jako Channel).
func (e Event) Flat() map[string]string {
	out := map[string]string{}
	for _, f := range wizardStd {
		if f == "EventID" && e.Code == 0 {
			continue
		}
		if v, ok := e.Get(f); ok && v != "" {
			out[f] = v
		}
	}
	for k, v := range e.Fields {
		if k == "winlog.channel" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// LogsourceFor zwraca logsource Sigmy dla zbioru danych i kanału zdarzenia
// (puste product – zbiór bez odpowiednika; reguła wybiera wtedy zdarzenia
// polem event.dataset).
func LogsourceFor(dataset, channel string) (product, service string) {
	switch {
	case strings.HasPrefix(dataset, "windows."):
		for name, ch := range services {
			if strings.EqualFold(ch, channel) {
				return "windows", name
			}
		}
		return "windows", ""
	case dataset == "fortinet.fortigate" || strings.HasPrefix(dataset, "fortinet.fortigate."):
		return "fortigate", ""
	case dataset == "mikrotik.routeros" || strings.HasPrefix(dataset, "mikrotik.routeros."):
		return "mikrotik", ""
	case strings.HasPrefix(dataset, "linux."):
		return "linux", ""
	case dataset == "pfsense.firewall":
		return "pfsense", ""
	case dataset == "cisco.asa":
		return "cisco", ""
	}
	for name, ds := range azureServices {
		if ds == dataset {
			return "azure", name
		}
	}
	return "", ""
}
