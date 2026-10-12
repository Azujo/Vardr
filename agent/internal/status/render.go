package status

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"siem/internal/contract"
)

// StaleAfter: status starszy niż ta wartość oznacza, że agent nie działa
// lub się zawiesił (zapis odbywa się co kilka sekund).
const StaleAfter = 30 * time.Second

var channelLabels = map[string]string{
	ChannelStarting:     "URUCHAMIANIE",
	ChannelOK:           "OK",
	ChannelNotFound:     "BRAK KANAŁU",
	ChannelAccessDenied: "BRAK DOSTĘPU",
	ChannelError:        "BŁĄD",
}

// Render wypisuje status w czytelnej postaci.
func Render(w io.Writer, s Status, now time.Time) {
	age := now.Sub(s.UpdatedAt)
	fmt.Fprintf(w, "Agent %s (wersja %s, PID %d), działa od %s\n",
		s.AgentID, s.Version, s.PID, s.StartedAt.Local().Format("2006-01-02 15:04:05"))
	if age > StaleAfter {
		fmt.Fprintf(w, "  UWAGA: status NIEAKTUALNY – ostatni zapis %s temu (agent zatrzymany lub zawieszony)\n", ago(age))
	} else {
		fmt.Fprintf(w, "  status z %s temu\n", ago(age))
	}

	fmt.Fprintf(w, "\nSerwer: %s\n", s.Server.URL)
	switch {
	case s.Server.Healthy:
		fmt.Fprintf(w, "  OK – ostatnia przyjęta paczka %s temu\n", ago(now.Sub(s.Server.LastAcceptedAt)))
	case s.Server.LastErrorAt.IsZero():
		fmt.Fprintln(w, "  jeszcze nic nie wysłano")
	default:
		fmt.Fprintf(w, "  PROBLEM – ostatni błąd %s temu: %s\n", ago(now.Sub(s.Server.LastErrorAt)), s.Server.LastError)
		if !s.Server.LastAcceptedAt.IsZero() {
			fmt.Fprintf(w, "  ostatnia przyjęta paczka %s temu\n", ago(now.Sub(s.Server.LastAcceptedAt)))
		}
	}

	fmt.Fprintln(w, "\nKanały:")
	for _, c := range s.Channels {
		label := channelLabels[c.State]
		if label == "" {
			label = strings.ToUpper(c.State)
		}
		line := fmt.Sprintf("  %-45s %-13s", c.Name, label)
		if c.LastRecordID > 0 {
			line += fmt.Sprintf(" rekord %d, odczyt %s temu, opóźnienie %s",
				c.LastRecordID, ago(now.Sub(c.LastReadAt)), ago(c.LastLag))
		}
		fmt.Fprintln(w, line)
		if c.Error != "" {
			fmt.Fprintf(w, "      %s\n", c.Error)
		}
	}

	k := s.Counters
	fmt.Fprintf(w, "\nLiczniki: odczytane %d, odfiltrowane %d, przyjęte przez serwer %d, przycięte %d, kwarantanna %d, ponowienia %d\n",
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
	fmt.Fprintf(w, "Limity:   %s\n", strings.Join(parts, " "))
	switch s.Config.Source {
	case "panel":
		fmt.Fprintf(w, "Konfig.:  z panelu – grupa %q, wersja %s (zastosowana %s)\n", s.Config.Group, s.Config.Version,
			s.Config.AppliedAt.Local().Format("2006-01-02 15:04:05"))
	case "local":
		fmt.Fprintln(w, "Konfig.:  lokalna (agent.yaml) – panel nie przysłał jeszcze konfiguracji")
	}
	fmt.Fprintf(w, "Dławienie od startu: EPS %s, łącze %s\n", s.Throttle.EPS.Round(time.Millisecond), s.Throttle.Bandwidth.Round(time.Millisecond))
	p := s.Process
	fmt.Fprintf(w, "Proces:   czas CPU %s, sterta Go %.1f MB (pamięć Go łącznie %.1f MB), gorutyny %d, GOMAXPROCS %d\n",
		p.CPUTime.Round(time.Millisecond), p.HeapMB, p.SysMB, p.Goroutines, p.MaxProcs)

	if b := s.Buffer; b != nil {
		switch {
		case b.Disabled:
			fmt.Fprintln(w, "Bufor:    wyłączony – przy braku łączności zdarzenia czekają w dzienniku Windows")
		case b.Batches == 0:
			fmt.Fprintf(w, "Bufor:    pusty (limit %d MB, po zapełnieniu: %s)\n", b.MaxBytes>>20, onFullLabel(b.OnFull))
		default:
			fmt.Fprintf(w, "Bufor:    %d paczek, %.1f MB z %d MB, najstarsza z %s – dosyłanie po powrocie serwera\n",
				b.Batches, float64(b.Bytes)/(1<<20), b.MaxBytes>>20, b.OldestAt.Local().Format("2006-01-02 15:04:05"))
		}
		if b.Full {
			fmt.Fprintf(w, "  PEŁNY – %s\n", onFullLabel(b.OnFull))
		}
		if b.Dropped > 0 {
			fmt.Fprintf(w, "  UTRACONO %d zdarzeń (usunięte z pełnego bufora)\n", b.Dropped)
		}
	}
	if c := s.Clock; !c.MeasuredAt.IsZero() || c.TimeService != "" {
		line := "Zegar:    "
		if !c.MeasuredAt.IsZero() {
			line += fmt.Sprintf("odchylenie od serwera %s (±%d ms, pomiar %s temu)", formatOffset(c.OffsetMs), c.UncertaintyMs,
				ago(now.Sub(c.MeasuredAt)))
		} else {
			line += "odchylenie jeszcze nie zmierzone"
		}
		if c.TimeService != "" {
			line += ", usługa czasu Windows: " + timeServiceLabel(c.TimeService)
		}
		fmt.Fprintln(w, line)
	}

	if m := s.Sysmon; m != nil {
		switch {
		case !m.Installed:
			fmt.Fprintln(w, "Sysmon:   nie zainstalowany")
		case !m.Running:
			fmt.Fprintf(w, "Sysmon:   ZATRZYMANY (%s %s)\n", m.Service, m.Version)
		default:
			fmt.Fprintf(w, "Sysmon:   działa (%s %s, konfiguracja %s)\n", m.Service, m.Version, m.ConfigHash)
		}
	}

	if p := s.Protection; p != nil {
		switch {
		case !p.Enabled:
			fmt.Fprintln(w, "Ochrona: wyłączona (grupa w panelu albo agent bez konfiguracji z panelu)")
		case p.Service == "protected":
			fmt.Fprintf(w, "Ochrona: włączona – zatrzymanie i deinstalacja tylko tokenem z panelu (tokeny ważne: %d)\n", p.Tokens)
		default:
			fmt.Fprintf(w, "Ochrona: włączona, ale usługa NIE jest chroniona (%s) %s\n", p.Service, p.Error)
		}
		for _, e := range p.Events {
			if now.Sub(e.At) > 24*time.Hour {
				continue
			}
			title := contract.TamperKinds[e.Kind].Title
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
		fmt.Fprintf(w, "UWAGA: %s\n", warn)
	}
}

func onFullLabel(s string) string {
	if s == "drop_oldest" {
		return "usuwanie najstarszych paczek"
	}
	return "wstrzymanie odczytu (zdarzenia czekają w dzienniku Windows)"
}

func formatOffset(ms int64) string {
	switch {
	case ms > 0:
		return fmt.Sprintf("+%s (agent się spieszy)", time.Duration(ms)*time.Millisecond)
	case ms < 0:
		return fmt.Sprintf("-%s (agent się spóźnia)", time.Duration(-ms)*time.Millisecond)
	}
	return "0"
}

func timeServiceLabel(s string) string {
	switch s {
	case "running":
		return "działa"
	case "stopped":
		return "zatrzymana (Windows uruchamia ją na żądanie)"
	case "disabled":
		return "WYŁĄCZONA"
	case "missing":
		return "BRAK"
	}
	return "nieznany stan"
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
		return fmt.Sprintf("%.0f dni", d.Hours()/24)
	}
}
