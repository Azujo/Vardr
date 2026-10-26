// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"siem/internal/alerts"
	"siem/internal/risk"
)

// Reguła wbudowana „ryzyko krytyczne” (wersja 1.3): osoba albo komputer
// wchodzi w poziom krytyczny scoringu ryzyka (internal/risk). Wiele
// drobnych alertów, z których żaden osobno nie jest groźny, razem daje
// sygnał. Wyniki liczy siem-detector co 5 minut; reguła tylko zgłasza
// przejście w poziom krytyczny (wyłączana w panelu jak korelacje).
const riskCriticalTitle = "Ryzyko krytyczne osoby lub komputera"

func riskText(lang string) alerts.RuleText {
	return alerts.RuleText{
		Title: pick(lang, riskCriticalTitle, "Critical risk of a person or computer"),
		Description: pick(lang, "Wynik ryzyka osoby albo komputera przekroczył próg poziomu krytycznego: suma punktów za alerty "+
			"(według poziomu, wygasających w czasie, z mnożnikiem dla kont uprzywilejowanych i komputerów krytycznych). "+
			"Alerty rozstrzygnięte jako fałszywy alarm albo uzasadnione działanie się nie liczą. Ustawienia: Ryzyko w panelu.",
			"The risk score of a person or computer crossed the critical level threshold: the sum of points for alerts "+
				"(by level, decaying over time, with a multiplier for privileged accounts and critical computers). Alerts "+
				"resolved as a false positive or legitimate activity do not count. Settings: Risk in the panel."),
		Instructions: pick(lang, "Otwórz wynik w module Ryzyko i przejrzyj alerty, które się na niego złożyły – czy to jedna "+
			"seria (np. skaner, błędna konfiguracja), czy różne działania tej samej osoby lub na tym samym komputerze. "+
			"Rozstrzygnij zamykane alerty (prawdziwy / uzasadnione / fałszywy alarm), żeby wynik odpowiadał rzeczywistości; "+
			"przy podejrzeniu przejęcia konta lub komputera – załóż incydent.",
			"Open the score in the Risk module and review the alerts that make it up – one series (e.g. a scanner, a "+
				"misconfiguration) or different activities of the same person or on the same computer. Resolve the alerts "+
				"you close (true / legitimate / false positive) so the score reflects reality; if you suspect a compromised "+
				"account or computer, open an incident."),
	}
}

// RiskRule opisuje regułę dla panelu.
func RiskRule() alerts.RuleInfo {
	pl := riskText("pl")
	// Technika zależy od alertów, które złożyły się na wynik.
	return alerts.RuleInfo{ID: risk.CriticalRuleID, Title: riskCriticalTitle, Level: "high", Mode: "correlation",
		Enabled: true, FileEnabled: true, File: "(wbudowana)", Tags: []string{"vardr.attack_dynamic"},
		Description: pl.Description,
		Source: "# Reguła wbudowana w siem-detector (server/internal/detector/riskrule.go),\n" +
			"# oceniana co 5 minut na wynikach scoringu ryzyka (internal/risk).\n",
		Instructions: pl.Instructions, I18n: ruleTexts(riskText)}
}

// RiskKey: klucz encji w wynikach i w poprzednich poziomach.
func RiskKey(s risk.Score) string { return s.Type + "\x00" + s.Entity }

// RiskCheck: alerty dla osób i komputerów, które właśnie weszły w poziom
// krytyczny (poprzedni poziom inny – prev z SaveRiskScores).
func RiskCheck(scores []risk.Score, prev map[string]string, now time.Time) []alerts.Hit {
	var hits []alerts.Hit
	for _, s := range scores {
		if s.Level != risk.Critical || prev[RiskKey(s)] == risk.Critical {
			continue
		}
		var rules []string
		for _, c := range s.Top {
			if len(rules) == 3 {
				break
			}
			if !slices.Contains(rules, c.RuleTitle) && c.RuleTitle != "" {
				rules = append(rules, c.RuleTitle)
			}
		}
		text := func(lang string) alerts.AlertText {
			who := pick(lang, "Osoba ", "Person ") + s.Display
			if s.Type == risk.Host {
				who = pick(lang, "Komputer ", "Computer ") + s.Display
			}
			return alerts.AlertText{
				Title: riskText(lang).Title,
				Summary: fmt.Sprintf(pick(lang, "%s: ryzyko krytyczne – %.0f pkt z %d alertów; największy udział: %s",
					"%s: critical risk – %.0f points from %d alerts; largest share: %s"),
					who, s.Score, s.Alerts, strings.Join(rules, "; ")),
				Instructions: riskText(lang).Instructions,
			}
		}
		pl := text("pl")
		key := "risk:" + s.Type + ":" + s.Entity
		h := alerts.Hit{RuleID: risk.CriticalRuleID, RuleTitle: riskCriticalTitle, Level: "high", Engine: "system",
			EventID: fmt.Sprintf("%s@%d", key, now.Unix()), EventTime: now, GroupKey: key,
			Summary: pl.Summary, Instructions: pl.Instructions, I18n: texts(text)}
		if s.Type == risk.Host {
			h.HostName = s.Display
		} else {
			h.UserName, h.Identity = s.Display, s.Entity
		}
		hits = append(hits, h)
	}
	return hits
}
