// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"strings"
	"testing"
	"time"

	"siem/internal/risk"
)

// Alert tylko przy wejściu w poziom krytyczny – encja krytyczna już
// w poprzedniej rundzie nie alarmuje ponownie co 5 minut.
func TestRiskCheckOnlyOnTransition(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	jan := risk.Score{Type: risk.User, Entity: "jan@azujo.pl", Display: "jan@azujo.pl", Score: 120, Level: risk.Critical, Alerts: 9,
		Top: []risk.Contribution{{RuleTitle: "Brute force"}, {RuleTitle: "Brute force"}, {RuleTitle: "Nowy kraj"}}}
	pc := risk.Score{Type: risk.Host, Entity: "dc1", Display: "DC1", Score: 140, Level: risk.Critical, Alerts: 4}
	ewa := risk.Score{Type: risk.User, Entity: "ewa", Display: "ewa", Score: 60, Level: risk.High}
	hits := RiskCheck([]risk.Score{jan, pc, ewa}, map[string]string{RiskKey(jan): risk.High, RiskKey(pc): risk.Critical}, now)
	if len(hits) != 1 {
		t.Fatalf("trafienia: %+v", hits)
	}
	h := hits[0]
	if h.RuleID != risk.CriticalRuleID || h.Identity != "jan@azujo.pl" || h.GroupKey != "risk:user:jan@azujo.pl" ||
		!strings.Contains(h.Summary, "120 pkt z 9 alertów") || !strings.Contains(h.Summary, "Brute force; Nowy kraj") {
		t.Fatalf("alert: %+v", h)
	}
	if en := h.I18n["en"]; !strings.Contains(en.Summary, "critical risk") {
		t.Fatalf("po angielsku: %+v", en)
	}
	if hits := RiskCheck([]risk.Score{pc}, map[string]string{}, now); len(hits) != 1 || hits[0].HostName != "DC1" {
		t.Fatalf("komputer: %+v", hits)
	}
}
