// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"fmt"
	"time"

	"siem/internal/alerts"
)

// Reguła wbudowana: utrata łączności z agentem (roadmapa, sekcja 11 –
// „utrata heartbeatu agenta”). Nie jest regułą Sigmy – ocenia heartbeat
// z panelu, nie zdarzenia. Próg ustawia się w grupie agentów (panel →
// Grupy agentów), bo stacje wyłączane na noc nie powinny alarmować.
const (
	HeartbeatRuleID    = "heimdall-agent-heartbeat-lost"
	heartbeatRuleTitle = "Utrata łączności z agentem"
)

// HeartbeatRule opisuje regułę wbudowaną dla panelu.
func HeartbeatRule() alerts.RuleInfo {
	return alerts.RuleInfo{ID: HeartbeatRuleID, Title: heartbeatRuleTitle, Level: "high", Mode: "system", Enabled: true, FileEnabled: true,
		File: "(wbudowana)", Tags: []string{"attack.defense_impairment", "attack.t1685", "attack.t1489"},
		Description: "Agent z grupy z ustawionym progiem („alarm po utracie łączności”) nie wysłał heartbeatu " +
			"przez zadany czas. Wyłączona usługa agenta, odcięta sieć albo wyłączony komputer – na serwerach " +
			"i kontrolerach domeny każde z nich wymaga wyjaśnienia. Alert zamyka się sam, gdy agent wróci.",
		Source: "# Reguła wbudowana w siem-detector (server/internal/detector/heartbeat.go).\n" +
			"# Próg: panel → Grupy agentów → „Alarm po utracie łączności”.\n",
		Instructions: "Sprawdź, czy komputer działa i ma sieć, oraz stan usługi SiemAgent. Zatrzymanie usługi " +
			"bez zgłoszenia traktuj jak próbę ukrycia działań – przejrzyj zdarzenia z tego komputera sprzed przerwy."}
}

// HeartbeatCheck: alerty dla agentów bez heartbeatu ponad próg grupy
// i lista agentów, które wróciły (ich alerty są zamykane). Każda przerwa
// (ostatni heartbeat) to jeden alert – identyfikator „zdarzenia” zawiera
// czas ostatniego heartbeatu.
func HeartbeatCheck(beats []alerts.AgentBeat, now time.Time) (hits []alerts.Hit, back []alerts.AgentBeat) {
	for _, b := range beats {
		if b.AlertAfter <= 0 {
			continue
		}
		gap := now.Sub(b.LastSeen)
		if gap <= b.AlertAfter {
			back = append(back, b)
			continue
		}
		host := b.Host
		if host == "" {
			host = b.ID
		}
		hits = append(hits, alerts.Hit{
			RuleID: HeartbeatRuleID, RuleTitle: heartbeatRuleTitle, Level: "high", Engine: "system",
			EventID:   fmt.Sprintf("heartbeat:%s:%d", b.ID, b.LastSeen.UnixMilli()),
			EventTime: b.LastSeen, AgentID: b.ID, HostName: b.Host, SourceIP: b.IP,
			GroupKey: HeartbeatKey(b.ID) + fmt.Sprint(b.LastSeen.UnixMilli()),
			Summary: fmt.Sprintf("komputer %s (grupa %s): brak heartbeatu od %s UTC (próg %s), ostatni adres %s, agent %s",
				host, b.Group, b.LastSeen.UTC().Format("2006-01-02 15:04:05"), fmtWindow(b.AlertAfter), b.IP, b.Version),
			Instructions: fmt.Sprintf("Agent %s na %s nie odzywa się od %s UTC. ", b.ID, host,
				b.LastSeen.UTC().Format("2006-01-02 15:04")) + HeartbeatRule().Instructions,
		})
	}
	return hits, back
}

// HeartbeatKey: prefiks klucza alertów agenta (zamykanie po powrocie).
func HeartbeatKey(agent string) string { return agent + "@" }
