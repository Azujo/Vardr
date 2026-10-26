// SPDX-License-Identifier: AGPL-3.0-or-later

package risk

import (
	"testing"
	"time"
)

func find(scores []Score, typ, key string) *Score {
	for i := range scores {
		if scores[i].Type == typ && scores[i].Entity == key {
			return &scores[i]
		}
	}
	return nil
}

// Seria alertów niskich i średnich jednej osoby z AD i Entra ID (ta sama
// tożsamość) podnosi ją do poziomu krytycznego; po rozstrzygnięciu części
// jako fałszywy alarm wynik spada (warunek ukończenia z roadmapy 17a).
func TestManySmallAlertsBecomeCritical(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var in []Input
	for i := range 20 {
		in = append(in, Input{AlertID: int64(i + 1), RuleID: "r", Level: "medium", LastSeen: now.Add(-time.Duration(i) * time.Hour),
			UserName: []string{`AZUJO\jan`, "jan@azujo.pl"}[i%2], UserIdentity: "jan@azujo.pl", HostName: "PC1"})
	}
	in = append(in, Input{AlertID: 99, RuleID: "r2", Level: "high", LastSeen: now, UserIdentity: "jan@azujo.pl", HostName: "PC2"})
	scores := Compute(in, Default(), now)
	jan := find(scores, User, "jan@azujo.pl")
	if jan == nil || jan.Level != Critical || jan.Alerts != 21 || jan.Score < 100 {
		t.Fatalf("osoba: %+v", jan)
	}
	if pc := find(scores, Host, "pc1"); pc == nil || pc.Display != "PC1" || pc.Alerts != 20 {
		t.Fatalf("komputer: %+v", pc)
	}
	if len(jan.Top) != MaxTop || jan.Top[0].AlertID != 99 {
		t.Fatalf("największe wkłady: %+v", jan.Top)
	}
	for i := range 8 {
		in[i].Resolution = FalsePositive
	}
	in[8].Resolution = Benign
	if jan := find(Compute(in, Default(), now), User, "jan@azujo.pl"); jan.Level == Critical || jan.Alerts != 12 {
		t.Fatalf("po fałszywych alarmach: %+v", jan)
	}
}

func TestDecayMultiplierAndExclusions(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cfg := Default()
	cfg.PrivilegedUsers = []string{"*.adm", "administrator"}
	cfg.CriticalGroups = []int64{7}
	in := []Input{
		{AlertID: 1, Level: "critical", LastSeen: now.Add(-14 * 24 * time.Hour), UserName: "ewa"},          // połowa: 20
		{AlertID: 2, Level: "high", LastSeen: now, UserName: `AZUJO\jan.adm`, HostName: "DC1", GroupID: 7}, // ×2: 30
		{AlertID: 3, Level: "high", LastSeen: now, UserName: "SYSTEM", HostName: "PC9$"},                   // konto systemowe
		{AlertID: 4, Level: "high", LastSeen: now, UserName: "PC9$"},                                       // konto komputera
		{AlertID: 5, RuleID: CriticalRuleID, Level: "high", LastSeen: now, UserName: "ewa"},                // alert o ryzyku
		{AlertID: 6, Level: "informational", LastSeen: now, UserName: "ola"},                               // 0 punktów
	}
	scores := Compute(in, cfg, now)
	if ewa := find(scores, User, "ewa"); ewa == nil || ewa.Score != 20 || ewa.Alerts != 1 {
		t.Fatalf("wygaszanie: %+v", ewa)
	}
	if adm := find(scores, User, `azujo\jan.adm`); adm == nil || adm.Score != 30 || !adm.Elevated {
		t.Fatalf("konto uprzywilejowane: %+v", adm)
	}
	if dc := find(scores, Host, "dc1"); dc == nil || dc.Score != 30 || !dc.Elevated {
		t.Fatalf("komputer krytyczny: %+v", dc)
	}
	for _, k := range []string{"system", "pc9$", "ola"} {
		if s := find(scores, User, k); s != nil {
			t.Errorf("%s nie powinno mieć wyniku: %+v", k, s)
		}
	}
	if pc := find(scores, Host, "pc9$"); pc == nil || pc.Score != 15 {
		t.Fatalf("komputer z alertu konta systemowego: %+v", pc)
	}
	// Ten sam komputer pod pełną i krótką nazwą; adres IP bez skracania.
	scores = Compute([]Input{
		{AlertID: 1, Level: "high", LastSeen: now, HostName: "PC1"},
		{AlertID: 2, Level: "high", LastSeen: now, HostName: "pc1.azujo.centrala"},
		{AlertID: 3, Level: "high", LastSeen: now, HostName: "10.0.0.5"},
	}, Default(), now)
	if pc := find(scores, Host, "pc1"); pc == nil || pc.Alerts != 2 || pc.Display != "pc1.azujo.centrala" {
		t.Fatalf("pełna i krótka nazwa: %+v", pc)
	}
	if ip := find(scores, Host, "10.0.0.5"); ip == nil {
		t.Fatalf("adres IP: %+v", scores)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Config){
		func(c *Config) { c.Thresholds[High] = 10 },
		func(c *Config) { c.HalfLifeDays = 0 },
		func(c *Config) { c.Multiplier = 50 },
		func(c *Config) { c.PrivilegedUsers = []string{"[x"} },
		func(c *Config) { delete(c.Points, "low") },
	}
	for i, f := range bad {
		c := Default()
		f(&c)
		if c.Validate() == nil {
			t.Errorf("zła konfiguracja %d przeszła", i)
		}
	}
	if (Config{}).Normalize().HalfLifeDays != 14 {
		t.Fatal("Normalize bez wartości domyślnych")
	}
}
