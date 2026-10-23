// SPDX-License-Identifier: AGPL-3.0-or-later

package status

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"siem/internal/contract"
	"siem/internal/lang"
)

// StaleAfter: status starszy niż ta wartość oznacza, że agent nie działa
// lub się zawiesił (zapis odbywa się co kilka sekund).
const StaleAfter = 30 * time.Second

var channelLabels = map[string][2]string{
	ChannelStarting:     {"URUCHAMIANIE", "STARTING"},
	ChannelOK:           {"OK", "OK"},
	ChannelNotFound:     {"BRAK KANAŁU", "NO CHANNEL"},
	ChannelAccessDenied: {"BRAK DOSTĘPU", "ACCESS DENIED"},
	ChannelError:        {"BŁĄD", "ERROR"},
}

// Render wypisuje status w czytelnej postaci.
func Render(w io.Writer, s Status, now time.Time) {
	age := now.Sub(s.UpdatedAt)
	fmt.Fprintf(w, lang.L("Agent %s (wersja %s, PID %d), działa od %s\n", "Agent %s (version %s, PID %d), running since %s\n"),
		s.AgentID, s.Version, s.PID, s.StartedAt.Local().Format("2006-01-02 15:04:05"))
	if age > StaleAfter {
		fmt.Fprintf(w, lang.L("  UWAGA: status NIEAKTUALNY – ostatni zapis %s temu (agent zatrzymany lub zawieszony)\n", "  WARNING: status OUTDATED – last written %s ago (agent stopped or hung)\n"), ago(age))
	} else {
		fmt.Fprintf(w, lang.L("  status z %s temu\n", "  status from %s ago\n"), ago(age))
	}

	fmt.Fprintf(w, lang.L("\nSerwer: %s\n", "\nServer: %s\n"), s.Server.URL)
	switch {
	case s.Server.Healthy:
		fmt.Fprintf(w, lang.L("  OK – ostatnia przyjęta paczka %s temu\n", "  OK – last accepted batch %s ago\n"), ago(now.Sub(s.Server.LastAcceptedAt)))
	case s.Server.LastErrorAt.IsZero():
		fmt.Fprintln(w, lang.L("  jeszcze nic nie wysłano", "  nothing sent yet"))
	default:
		fmt.Fprintf(w, lang.L("  PROBLEM – ostatni błąd %s temu: %s\n", "  PROBLEM – last error %s ago: %s\n"), ago(now.Sub(s.Server.LastErrorAt)), s.Server.LastError)
		if !s.Server.LastAcceptedAt.IsZero() {
			fmt.Fprintf(w, lang.L("  ostatnia przyjęta paczka %s temu\n", "  last accepted batch %s ago\n"), ago(now.Sub(s.Server.LastAcceptedAt)))
		}
	}

	fmt.Fprintln(w, lang.L("\nKanały:", "\nChannels:"))
	for _, c := range s.Channels {
		label := lang.L(channelLabels[c.State][0], channelLabels[c.State][1])
		if label == "" {
			label = strings.ToUpper(c.State)
		}
		line := fmt.Sprintf("  %-45s %-13s", c.Name, label)
		if c.LastRecordID > 0 {
			line += fmt.Sprintf(lang.L(" rekord %d, odczyt %s temu, opóźnienie %s", " record %d, read %s ago, lag %s"),
				c.LastRecordID, ago(now.Sub(c.LastReadAt)), ago(c.LastLag))
		}
		fmt.Fprintln(w, line)
		if c.Error != "" {
			fmt.Fprintf(w, "      %s\n", c.Error)
		}
	}

	k := s.Counters
	fmt.Fprintf(w, lang.L("\nLiczniki: odczytane %d, odfiltrowane %d, przyjęte przez serwer %d, przycięte %d, kwarantanna %d, ponowienia %d\n", "\nCounters: read %d, filtered %d, accepted by the server %d, truncated %d, quarantined %d, retries %d\n"),
		k.Read, k.Filtered, k.Accepted, k.Truncated, k.Quarantined, k.Retries)

	keys := make([]string, 0, len(s.Limits))
	for key := range s.Limits {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, s.Limits[key]))
	}
	fmt.Fprintf(w, lang.L("Limity:   %s\n", "Limits:   %s\n"), strings.Join(parts, " "))
	switch s.Config.Source {
	case "panel":
		fmt.Fprintf(w, lang.L("Konfig.:  z panelu – grupa %q, wersja %s (zastosowana %s)\n", "Config:   from the panel – group %q, version %s (applied %s)\n"), s.Config.Group, s.Config.Version,
			s.Config.AppliedAt.Local().Format("2006-01-02 15:04:05"))
	case "local":
		fmt.Fprintln(w, lang.L("Konfig.:  lokalna (agent.yaml) – panel nie przysłał jeszcze konfiguracji", "Config:   local (agent.yaml) – the panel has not sent a configuration yet"))
	}
	fmt.Fprintf(w, lang.L("Dławienie od startu: EPS %s, łącze %s\n", "Throttling since start: EPS %s, bandwidth %s\n"), s.Throttle.EPS.Round(time.Millisecond), s.Throttle.Bandwidth.Round(time.Millisecond))
	p := s.Process
	fmt.Fprintf(w, lang.L("Proces:   czas CPU %s, sterta Go %.1f MB (pamięć Go łącznie %.1f MB), gorutyny %d, GOMAXPROCS %d\n", "Process:  CPU time %s, Go heap %.1f MB (Go memory total %.1f MB), goroutines %d, GOMAXPROCS %d\n"),
		p.CPUTime.Round(time.Millisecond), p.HeapMB, p.SysMB, p.Goroutines, p.MaxProcs)

	if b := s.Buffer; b != nil {
		switch {
		case b.Disabled:
			fmt.Fprintln(w, lang.L("Bufor:    wyłączony – przy braku łączności zdarzenia czekają w dzienniku Windows", "Buffer:   disabled – without a connection events wait in the Windows event log"))
		case b.Batches == 0:
			fmt.Fprintf(w, lang.L("Bufor:    pusty (limit %d MB, po zapełnieniu: %s)\n", "Buffer:   empty (limit %d MB, when full: %s)\n"), b.MaxBytes>>20, onFullLabel(b.OnFull))
		default:
			fmt.Fprintf(w, lang.L("Bufor:    %d paczek, %.1f MB z %d MB, najstarsza z %s – dosyłanie po powrocie serwera\n", "Buffer:   %d batches, %.1f MB of %d MB, oldest from %s – sent when the server is back\n"),
				b.Batches, float64(b.Bytes)/(1<<20), b.MaxBytes>>20, b.OldestAt.Local().Format("2006-01-02 15:04:05"))
		}
		if b.Full {
			fmt.Fprintf(w, lang.L("  PEŁNY – %s\n", "  FULL – %s\n"), onFullLabel(b.OnFull))
		}
		if b.Dropped > 0 {
			fmt.Fprintf(w, lang.L("  UTRACONO %d zdarzeń (usunięte z pełnego bufora)\n", "  LOST %d events (removed from the full buffer)\n"), b.Dropped)
		}
	}
	if c := s.Clock; !c.MeasuredAt.IsZero() || c.TimeService != "" {
		line := lang.L("Zegar:    ", "Clock:    ")
		if !c.MeasuredAt.IsZero() {
			line += fmt.Sprintf(lang.L("odchylenie od serwera %s (±%d ms, pomiar %s temu)", "offset from the server %s (±%d ms, measured %s ago)"), formatOffset(c.OffsetMs), c.UncertaintyMs,
				ago(now.Sub(c.MeasuredAt)))
		} else {
			line += lang.L("odchylenie jeszcze nie zmierzone", "offset not measured yet")
		}
		if c.TimeService != "" {
			line += lang.L(", usługa czasu Windows: ", ", Windows Time service: ") + timeServiceLabel(c.TimeService)
		}
		fmt.Fprintln(w, line)
	}

	if m := s.Sysmon; m != nil {
		switch {
		case !m.Installed:
			fmt.Fprintln(w, lang.L("Sysmon:   nie zainstalowany", "Sysmon:   not installed"))
		case !m.Running:
			fmt.Fprintf(w, lang.L("Sysmon:   ZATRZYMANY (%s %s)\n", "Sysmon:   STOPPED (%s %s)\n"), m.Service, m.Version)
		default:
			fmt.Fprintf(w, lang.L("Sysmon:   działa (%s %s, konfiguracja %s)\n", "Sysmon:   running (%s %s, configuration %s)\n"), m.Service, m.Version, m.ConfigHash)
		}
	}

	if p := s.Protection; p != nil {
		switch {
		case !p.Enabled:
			fmt.Fprintln(w, lang.L("Ochrona: wyłączona (grupa w panelu albo agent bez konfiguracji z panelu)", "Protection: disabled (group in the panel or agent without configuration from the panel)"))
		case p.Service == "protected":
			fmt.Fprintf(w, lang.L("Ochrona: włączona – zatrzymanie i deinstalacja tylko tokenem z panelu (tokeny ważne: %d)\n", "Protection: enabled – stopping and uninstalling only with a token from the panel (valid tokens: %d)\n"), p.Tokens)
		default:
			fmt.Fprintf(w, lang.L("Ochrona: włączona, ale usługa NIE jest chroniona (%s) %s\n", "Protection: enabled, but the service is NOT protected (%s) %s\n"), p.Service, p.Error)
		}
		for _, e := range p.Events {
			if now.Sub(e.At) > 24*time.Hour {
				continue
			}
			title := lang.L(contract.TamperKinds[e.Kind].Title, contract.TamperKinds[e.Kind].TitleEn)
			if title == "" {
				title = e.Kind
			}
			line := fmt.Sprintf("  %s %s", e.At.Local().Format("2006-01-02 15:04:05"), title)
			if e.User != "" {
				line += " – " + e.User
			}
			if e.Detail != "" {
				line += " (" + e.Detail + ")"
			}
			fmt.Fprintln(w, line)
		}
	}

	for _, warn := range s.Warnings {
		fmt.Fprintf(w, lang.L("UWAGA: %s\n", "WARNING: %s\n"), warn)
	}
}

func onFullLabel(s string) string {
	if s == "drop_oldest" {
		return lang.L("usuwanie najstarszych paczek", "removing the oldest batches")
	}
	return lang.L("wstrzymanie odczytu (zdarzenia czekają w dzienniku Windows)", "pausing reading (events wait in the Windows event log)")
}

func formatOffset(ms int64) string {
	switch {
	case ms > 0:
		return fmt.Sprintf(lang.L("+%s (agent się spieszy)", "+%s (the agent is ahead)"), time.Duration(ms)*time.Millisecond)
	case ms < 0:
		return fmt.Sprintf(lang.L("-%s (agent się spóźnia)", "-%s (the agent is behind)"), time.Duration(-ms)*time.Millisecond)
	}
	return "0"
}

func timeServiceLabel(s string) string {
	switch s {
	case "running":
		return lang.L("działa", "running")
	case "stopped":
		return lang.L("zatrzymana (Windows uruchamia ją na żądanie)", "stopped (Windows starts it on demand)")
	case "disabled":
		return lang.L("WYŁĄCZONA", "DISABLED")
	case "missing":
		return lang.L("BRAK", "MISSING")
	}
	return lang.L("nieznany stan", "unknown state")
}

func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	case d < 48*time.Hour:
		return d.Round(time.Minute).String()
	default:
		return fmt.Sprintf(lang.L("%.0f dni", "%.0f days"), d.Hours()/24)
	}
}
