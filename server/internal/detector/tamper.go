package detector

import (
	"fmt"
	"time"

	"siem/internal/alerts"
	"siem/internal/contract"
)

// Reguła wbudowana: sabotaż agenta (ochrona agenta, etap 8). Agent zapisuje
// zdarzenia ochrony w dzienniku i wysyła ostatnie w heartbeacie
// (status.protection.events) – zatrzymanie usługi bez tokenu, zabicie
// procesu, zmiana uprawnień albo konfiguracji usługi, zły token. Każde
// zdarzenie to jeden alert (identyfikator zdarzenia agenta), także gdy
// dotrze z opóźnieniem (po ponownym uruchomieniu agenta).
const (
	TamperRuleID    = "heimdall-agent-tamper"
	tamperRuleTitle = "Próba sabotażu agenta"
	// upgradeGrace: agent zatrzymany przez instalator (aktualizacja) ma tyle
	// czasu na powrót – potem alert (podszycie się pod aktualizację).
	upgradeGrace = 15 * time.Minute
)

// TamperRule opisuje regułę wbudowaną dla panelu.
func TamperRule() alerts.RuleInfo {
	return alerts.RuleInfo{ID: TamperRuleID, Title: tamperRuleTitle, Level: "high", Mode: "system", Enabled: true, FileEnabled: true,
		File: "(wbudowana)", Tags: []string{"attack.defense_evasion", "attack.t1562.001", "attack.t1489"},
		Description: "Agent zgłosił próbę wyłączenia albo obejścia ochrony: zatrzymanie usługi bez tokenu deinstalacji, " +
			"zabicie procesu, zmianę uprawnień lub konfiguracji usługi (agent ją cofnął), nieudaną próbę zatrzymania " +
			"albo deinstalacji (zły lub brak tokenu), a także aktualizację, po której agent nie wrócił w ciągu 15 min. " +
			"Zatrzymanie i deinstalacja tokenem z panelu nie wywołują alertu.",
		Source: "# Reguła wbudowana w siem-detector (server/internal/detector/tamper.go).\n" +
			"# Zdarzenia: agent/internal/guard (dziennik ochrony w katalogu stanu agenta).\n" +
			"# Ochronę włącza i wyłącza grupa agentów (panel → Grupy agentów).\n",
		Instructions: "Ustal, kto był zalogowany na komputerze (4624/4672 w Mímirze) i czy były zgłoszone prace. " +
			"Zatrzymanie z pominięciem tokenu albo zmiana uprawnień usługi to typowe przygotowanie do działań, które " +
			"mają nie zostać zauważone – przejrzyj zdarzenia z tego komputera z okresu wokół zgłoszenia."}
}

// TamperCheck zwraca alerty dla zdarzeń ochrony z poziomem alertu (także
// zatrzymania „tokenem”, którego panel nie wydał) oraz dla agentów
// zatrzymanych przez instalator, które nie wróciły w ciągu 15 min.
func TamperCheck(beats []alerts.TamperBeat, now time.Time) []alerts.Hit {
	var hits []alerts.Hit
	for _, b := range beats {
		host := b.Host
		if host == "" {
			host = b.ID
		}
		for _, e := range b.Events {
			kind, ok := contract.TamperKinds[e.Kind]
			if (e.Kind == contract.TamperStopToken || e.Kind == contract.TamperUninstallTok ||
				(e.Kind == contract.TamperUpgrade && e.TokenID != "")) && !b.Tokens[e.TokenID] {
				// Token, którego panel nie wydał temu agentowi – podrobiona
				// konfiguracja agenta (skrót tokenu podsunięty przez administratora).
				kind, ok = contract.TamperKind{Level: "high", Title: kind.Title + " – token nieznany panelowi (podrobiona konfiguracja agenta?)"}, true
			}
			if !ok || kind.Level == "" || e.ID == "" || now.Sub(e.At) > 7*24*time.Hour {
				continue
			}
			summary := fmt.Sprintf("komputer %s (grupa %s): %s", host, b.Group, kind.Title)
			if e.User != "" {
				summary += " – konto " + e.User
			}
			if e.Detail != "" {
				summary += " (" + e.Detail + ")"
			}
			hits = append(hits, alerts.Hit{
				RuleID: TamperRuleID, RuleTitle: tamperRuleTitle, Level: kind.Level, Engine: "system",
				EventID: "tamper:" + b.ID + ":" + e.ID, EventTime: e.At, AgentID: b.ID, HostName: b.Host, SourceIP: b.IP,
				UserName: e.User, GroupKey: b.ID + "@tamper:" + e.ID, Summary: summary,
				Instructions: fmt.Sprintf("%s na %s o %s UTC. ", kind.Title, host, e.At.UTC().Format("2006-01-02 15:04:05")) +
					TamperRule().Instructions,
			})
		}
		if b.Stopping == contract.TamperUpgrade && now.Sub(b.LastSeen) > upgradeGrace {
			hits = append(hits, alerts.Hit{
				RuleID: TamperRuleID, RuleTitle: tamperRuleTitle, Level: "high", Engine: "system",
				EventID:   fmt.Sprintf("upgrade:%s:%d", b.ID, b.LastSeen.UnixMilli()),
				EventTime: b.LastSeen, AgentID: b.ID, HostName: b.Host, SourceIP: b.IP,
				GroupKey: fmt.Sprintf("%s@upgrade:%d", b.ID, b.LastSeen.UnixMilli()),
				Summary: fmt.Sprintf("komputer %s (grupa %s): agent zatrzymany przez instalator (aktualizacja) o %s UTC i nie wrócił "+
					"w ciągu %d min", host, b.Group, b.LastSeen.UTC().Format("2006-01-02 15:04"), int(upgradeGrace.Minutes())),
				Instructions: "Aktualizacja agenta trwa kilka sekund. Agent, który po niej nie wrócił, to nieudana aktualizacja " +
					"albo deinstalacja podszyta pod aktualizację (MSI z konta SYSTEM). Sprawdź usługę SiemAgent i msi.log " +
					"w %ProgramData%\\SiemAgent. " + TamperRule().Instructions,
			})
		}
	}
	return hits
}
