package status

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
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
	fmt.Fprintf(w, "Dławienie od startu: EPS %s, łącze %s\n", s.Throttle.EPS.Round(time.Millisecond), s.Throttle.Bandwidth.Round(time.Millisecond))
	p := s.Process
	fmt.Fprintf(w, "Proces:   czas CPU %s, sterta Go %.1f MB (pamięć Go łącznie %.1f MB), gorutyny %d, GOMAXPROCS %d\n",
		p.CPUTime.Round(time.Millisecond), p.HeapMB, p.SysMB, p.Goroutines, p.MaxProcs)

	for _, warn := range s.Warnings {
		fmt.Fprintf(w, "UWAGA: %s\n", warn)
	}
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
