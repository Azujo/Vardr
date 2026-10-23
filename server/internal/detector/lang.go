// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"siem/internal/alerts"
	"siem/internal/detect"
)

// Teksty alertów w językach tłumaczeń: detektor zapisuje przy alercie
// tytuł, opis i instrukcję w każdym języku z detect.Languages (pola
// trafienia – po polsku), a panel i powiadomienia wybierają język
// czytającego. Teksty wbudowane detektora są w parach polski/angielski.

// pick: tekst polski albo angielski (dla „en”).
func pick(lang, pl, en string) string {
	if lang == "en" {
		return en
	}
	return pl
}

// texts: tłumaczenia trafienia – f podaje tytuł, opis i instrukcję w języku.
func texts(f func(lang string) alerts.AlertText) map[string]alerts.AlertText {
	out := make(map[string]alerts.AlertText, len(detect.Languages))
	for _, l := range detect.Languages {
		out[l] = f(l)
	}
	return out
}

// ruleTexts: tłumaczenia opisu reguły wbudowanej (tytuł, opis, instrukcja).
func ruleTexts(f func(lang string) alerts.RuleText) map[string]alerts.RuleText {
	out := make(map[string]alerts.RuleText, len(detect.Languages))
	for _, l := range detect.Languages {
		out[l] = f(l)
	}
	return out
}

// fromRule: tłumaczenia reguły z pliku (vardr.i18n) dla panelu.
func fromRule(m map[string]detect.RuleText) map[string]alerts.RuleText {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]alerts.RuleText, len(m))
	for l, t := range m {
		out[l] = alerts.RuleText{Title: t.Title, Description: t.Description, Instructions: t.Instructions}
	}
	return out
}
