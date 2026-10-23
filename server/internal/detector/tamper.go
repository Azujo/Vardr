// SPDX-License-Identifier: AGPL-3.0-or-later

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

// tamperText: tytuł, opis i instrukcja reguły w języku.
func tamperText(lang string) alerts.RuleText {
	return alerts.RuleText{
		Title: pick(lang, tamperRuleTitle, "Agent tampering attempt"),
		Description: pick(lang, "Agent zgłosił próbę wyłączenia albo obejścia ochrony: zatrzymanie usługi bez tokenu deinstalacji, "+
			"zabicie procesu, zmianę uprawnień lub konfiguracji usługi (agent ją cofnął), nieudaną próbę zatrzymania "+
			"albo deinstalacji (zły lub brak tokenu), a także aktualizację, po której agent nie wrócił w ciągu 15 min. "+
			"Zatrzymanie i deinstalacja tokenem z panelu nie wywołują alertu.",
			"The agent reported an attempt to disable or bypass its protection: stopping the service without an uninstall "+
				"token, killing the process, changing the service permissions or configuration (the agent reverted it), a failed "+
				"stop or uninstall attempt (wrong or no token), and an upgrade after which the agent did not return within 15 min. "+
				"Stopping and uninstalling with a token from the panel does not raise an alert."),
		Instructions: pick(lang, "Ustal, kto był zalogowany na komputerze (4624/4672 w Mímirze) i czy były zgłoszone prace. "+
			"Zatrzymanie z pominięciem tokenu albo zmiana uprawnień usługi to typowe przygotowanie do działań, które "+
			"mają nie zostać zauważone – przejrzyj zdarzenia z tego komputera z okresu wokół zgłoszenia.",
			"Find out who was signed in on the computer (4624/4672 in Mímir) and whether any work was scheduled. "+
				"Stopping without a token or changing the service permissions is typical preparation for actions meant to go "+
				"unnoticed – review the events from this computer around the time of the report."),
	}
}

func tamperKindTitle(lang, kind string) string {
	if k, ok := contract.TamperKinds[kind]; ok {
		return pick(lang, k.Title, k.TitleEn)
	}
	return kind
}

// TamperRule opisuje regułę wbudowaną dla panelu.
func TamperRule() alerts.RuleInfo {
	pl := tamperText("pl")
	return alerts.RuleInfo{ID: TamperRuleID, Title: tamperRuleTitle, Level: "high", Mode: "system", Enabled: true, FileEnabled: true,
		File: "(wbudowana)", Tags: []string{"attack.defense_impairment", "attack.t1685", "attack.t1489"},
		Description: pl.Description,
		Source: "# Reguła wbudowana w siem-detector (server/internal/detector/tamper.go).\n" +
			"# Zdarzenia: agent/internal/guard (dziennik ochrony w katalogu stanu agenta).\n" +
			"# Ochronę włącza i wyłącza grupa agentów (panel → Grupy agentów).\n",
		Instructions: pl.Instructions, I18n: ruleTexts(tamperText)}
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
			// Token, którego panel nie wydał temu agentowi – podrobiona
			// konfiguracja agenta (skrót tokenu podsunięty przez administratora).
			forged := (e.Kind == contract.TamperStopToken || e.Kind == contract.TamperUninstallTok ||
				(e.Kind == contract.TamperUpgrade && e.TokenID != "")) && !b.Tokens[e.TokenID]
			if forged {
				kind, ok = contract.TamperKind{Level: "high", Title: kind.Title}, true
			}
			if !ok || kind.Level == "" || e.ID == "" || now.Sub(e.At) > 7*24*time.Hour {
				continue
			}
			text := func(lang string) alerts.AlertText {
				title := tamperKindTitle(lang, e.Kind)
				if forged {
					title += pick(lang, " – token nieznany panelowi (podrobiona konfiguracja agenta?)",
						" – token unknown to the panel (forged agent configuration?)")
				}
				summary := fmt.Sprintf(pick(lang, "komputer %s (grupa %s): %s", "computer %s (group %s): %s"), host, b.Group, title)
				if e.User != "" {
					summary += pick(lang, " – konto ", " – account ") + e.User
				}
				if e.Detail != "" {
					summary += " (" + e.Detail + ")"
				}
				return alerts.AlertText{Title: tamperText(lang).Title, Summary: summary,
					Instructions: fmt.Sprintf(pick(lang, "%s na %s o %s UTC. ", "%s on %s at %s UTC. "), title, host,
						e.At.UTC().Format("2006-01-02 15:04:05")) + tamperText(lang).Instructions}
			}
			pl := text("pl")
			hits = append(hits, alerts.Hit{
				RuleID: TamperRuleID, RuleTitle: tamperRuleTitle, Level: kind.Level, Engine: "system",
				EventID: "tamper:" + b.ID + ":" + e.ID, EventTime: e.At, AgentID: b.ID, HostName: b.Host, SourceIP: b.IP,
				UserName: e.User, GroupKey: b.ID + "@tamper:" + e.ID, Summary: pl.Summary, Instructions: pl.Instructions,
				I18n: texts(text),
			})
		}
		if b.Stopping == contract.TamperUpgrade && now.Sub(b.LastSeen) > upgradeGrace {
			text := func(lang string) alerts.AlertText {
				return alerts.AlertText{Title: tamperText(lang).Title,
					Summary: fmt.Sprintf(pick(lang, "komputer %s (grupa %s): agent zatrzymany przez instalator (aktualizacja) o %s UTC i nie wrócił "+
						"w ciągu %d min", "computer %s (group %s): agent stopped by the installer (upgrade) at %s UTC and did not return "+
						"within %d min"), host, b.Group, b.LastSeen.UTC().Format("2006-01-02 15:04"), int(upgradeGrace.Minutes())),
					Instructions: pick(lang, "Aktualizacja agenta trwa kilka sekund. Agent, który po niej nie wrócił, to nieudana aktualizacja "+
						"albo deinstalacja podszyta pod aktualizację (MSI z konta SYSTEM). Sprawdź usługę SiemAgent i msi.log "+
						"w %ProgramData%\\SiemAgent. ", "An agent upgrade takes a few seconds. An agent that did not return after it means a "+
						"failed upgrade or an uninstall disguised as an upgrade (MSI from the SYSTEM account). Check the SiemAgent service and "+
						"msi.log in %ProgramData%\\SiemAgent. ") + tamperText(lang).Instructions}
			}
			pl := text("pl")
			hits = append(hits, alerts.Hit{
				RuleID: TamperRuleID, RuleTitle: tamperRuleTitle, Level: "high", Engine: "system",
				EventID:   fmt.Sprintf("upgrade:%s:%d", b.ID, b.LastSeen.UnixMilli()),
				EventTime: b.LastSeen, AgentID: b.ID, HostName: b.Host, SourceIP: b.IP,
				GroupKey: fmt.Sprintf("%s@upgrade:%d", b.ID, b.LastSeen.UnixMilli()),
				Summary:  pl.Summary, Instructions: pl.Instructions, I18n: texts(text),
			})
		}
	}
	return hits
}
