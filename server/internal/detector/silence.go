package detector

import (
	"context"
	"fmt"
	"sort"
	"time"

	"siem/internal/alerts"
)

// Reguła wbudowana „cisza źródła” (przegląd etapu 6): urządzenie syslog
// (router, zapora) albo połączenie z chmurą (konektor Entra ID) przestaje
// przysyłać zdarzenia. Utrata kolektora czy konektora wywołuje alert utraty
// łączności, ale cisza jednego urządzenia za działającym kolektorem – nie.
//
// Próg dopasowuje się do źródła: najdłuższa przerwa między godzinami ze
// zdarzeniami w ostatnich 7 dniach + 1 h (co najmniej SIEM_SOURCE_SILENCE_MIN,
// domyślnie 1 h). Zapora logująca bez przerwy alarmuje po ok. 2 h ciszy,
// domowy router cichy nocami – dopiero po dłuższej przerwie niż zwykła noc.
// Źródła rzadkie (zdarzenia w mniej niż 24 godzinach tygodnia) są pomijane.
// Zdarzenia Windows mają własną kontrolę (heartbeat agenta).
const (
	SourceSilentID    = "heimdall-source-silent"
	silenceLookback   = 7 * 24 * time.Hour
	silenceMinHours   = 24
	sourceSilentTitle = "Cisza źródła zdarzeń"
)

// apiSourceSQL: zdarzenia z API chmury (decode.IsAPI – dostawca „entra:…”).
// Komputer w takim zdarzeniu to urządzenie użytkownika, nie źródło.
const apiSourceSQL = `startsWith(event_provider, 'entra:')`

// SilenceRule opisuje regułę dla panelu (wyłączana jak korelacje).
func SilenceRule() alerts.RuleInfo {
	return alerts.RuleInfo{ID: SourceSilentID, Title: sourceSilentTitle, Level: "medium", Mode: "correlation",
		Enabled: true, FileEnabled: true, File: "(wbudowana)", Tags: []string{"attack.defense_impairment", "attack.t1685"},
		Description: "Urządzenie wysyłające syslog (router, zapora) albo połączenie z chmurą (Entra ID) nie przysłało " +
			"zdarzeń dłużej niż zwykle: próg to najdłuższa przerwa z ostatnich 7 dni + 1 h. Wyłączone logowanie na " +
			"urządzeniu, zmieniony adres serwera syslog, awaria urządzenia albo wygasłe uprawnienia aplikacji w chmurze. " +
			"Alert zamyka się sam, gdy zdarzenia wrócą.",
		Source: "# Reguła wbudowana w siem-detector (server/internal/detector/silence.go),\n" +
			"# oceniana co 5 minut w ClickHouse na zdarzeniach spoza Windows.\n",
		Instructions: "Sprawdź, czy urządzenie działa i nadal ma ustawiony serwer syslog Heimdalla (kolektor), albo – dla " +
			"chmury – stan konektora i uprawnień aplikacji. Wyłączenie logowania bez zgłoszenia traktuj jak próbę ukrycia " +
			"działań: przejrzyj ostatnie zdarzenia źródła (logowania administratorów, zmiany konfiguracji)."}
}

// Source to źródło zdarzeń spoza Windows: urządzenie syslog (Host) albo
// połączenie z chmurą (Dataset, bez Host).
type Source struct {
	Agent, Host, Dataset string
	Last                 time.Time
	Hours                []time.Time // godziny ze zdarzeniami (rosnąco)
}

// Key: prefiks klucza alertów źródła (zamykanie po powrocie).
func (s Source) Key() string { return "silent:" + s.Agent + "/" + s.Host + "/" + s.Dataset + "@" }

func (s Source) name() string {
	if s.Host != "" {
		return s.Host
	}
	return s.Dataset
}

// Sources czyta źródła z ostatnich 7 dni.
func (c *Correlator) Sources(ctx context.Context, now time.Time) ([]Source, error) {
	t := c.Events
	if t == "" {
		t = "siem.events"
	}
	q := fmt.Sprintf(`SELECT agent_id, if(api, '', host_name) AS host, if(api, event_dataset, '') AS ds,
			max(ingested), arraySort(groupUniqArray(toStartOfHour(ingested)))
		FROM (SELECT agent_id, host_name, event_dataset, ingested, %[2]s AS api FROM %[1]s
			WHERE ingested >= fromUnixTimestamp64Milli(%[3]d, 'UTC') AND NOT startsWith(event_dataset, 'windows.') AND event_dataset != '')
		GROUP BY agent_id, host, ds`, t, apiSourceSQL, now.Add(-silenceLookback).UnixMilli())
	rows, err := c.Conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.Agent, &s.Host, &s.Dataset, &s.Last, &s.Hours); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SilenceCheck: alerty dla źródeł cichych ponad swój próg i klucze źródeł,
// które nadają (ich otwarte alerty są zamykane). Każda przerwa (ostatnie
// zdarzenie) to jeden alert.
func SilenceCheck(srcs []Source, now time.Time, minSilence time.Duration) (hits []alerts.Hit, back []string) {
	for _, s := range srcs {
		if len(s.Hours) < silenceMinHours {
			continue
		}
		hours := append([]time.Time(nil), s.Hours...)
		sort.Slice(hours, func(i, j int) bool { return hours[i].Before(hours[j]) })
		var longest time.Duration
		for i := 1; i < len(hours); i++ {
			longest = max(longest, hours[i].Sub(hours[i-1]))
		}
		limit := max(minSilence, longest+time.Hour)
		silence := now.Sub(s.Last)
		if silence <= limit {
			back = append(back, s.Key())
			continue
		}
		what := "urządzenie " + s.Host
		if s.Host == "" {
			what = "źródło " + s.Dataset
		}
		last := s.Last.UTC().Format("2006-01-02 15:04")
		hits = append(hits, alerts.Hit{
			RuleID: SourceSilentID, RuleTitle: sourceSilentTitle, Level: "medium", Engine: "system",
			EventID:   fmt.Sprintf("%s%d", s.Key(), s.Last.UnixMilli()),
			EventTime: s.Last, AgentID: s.Agent, HostName: s.Host,
			GroupKey: s.Key() + fmt.Sprint(s.Last.UnixMilli()),
			Summary: fmt.Sprintf("%s (przez %s): brak zdarzeń od %s UTC – %s; najdłuższa przerwa w ostatnich 7 dniach %s",
				what, s.Agent, last, fmtSpan(silence), fmtSpan(longest)),
			Instructions: fmt.Sprintf("Źródło %s (agent %s) nie przysyła zdarzeń od %s UTC – dłużej niż zwykle (próg %s). ",
				s.name(), s.Agent, last, fmtSpan(limit)) + SilenceRule().Instructions,
		})
	}
	return hits, back
}

// fmtSpan: czas przerwy po ludzku (min, h i min, dni i h).
func fmtSpan(d time.Duration) string {
	d = d.Truncate(time.Minute)
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d dni %d h", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%d h %d min", d/time.Hour, d%time.Hour/time.Minute)
	}
	return fmt.Sprintf("%d min", d/time.Minute)
}
