package detector

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"siem/internal/detect"
	"siem/internal/model"
)

// Reguły taktyk ATT&CK na korpusie testu zgodności: które zdarzenia trafiają
// (przypadki graniczne z korpusu – bez trafień).
func TestTacticRules(t *testing.T) {
	rules, errs, err := detect.LoadDir("../../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	rules = ownRules(rules)
	events := buildCorpus()
	sort.SliceStable(events, func(i, j int) bool { return events[i].Ingested.Before(events[j].Ingested) })
	e := NewEngine()
	e.SetRules(rules)
	byRule := map[string][]string{}
	for i := 0; i < len(events); i += 5 {
		hits, _ := e.Evaluate(&model.Batch{Events: events[i:min(i+5, len(events))]})
		for _, h := range hits {
			ev := events[slices.IndexFunc(events, func(x model.Event) bool { return x.ID == h.EventID })]
			v := ev.HostName
			if ev.SourceIP != "" && strings.HasPrefix(ev.Dataset, "fortinet") {
				v = ev.SourceIP
			}
			if s := ev.Fields["ServiceName"]; s != "" {
				v += "/" + s
			}
			if u := ev.UserName; u != "" && ev.Code == 4624 {
				v += "/" + u
			}
			byRule[h.RuleID] = append(byRule[h.RuleID], v)
		}
	}
	uniq := func(s []string) string {
		s = slices.Clone(s)
		slices.Sort(s)
		return strings.Join(slices.Compact(s), ",")
	}
	for _, c := range []struct {
		rule, hosts string
		n           int
	}{
		{"b87aa5d4-4827-449f-a0d0-6285452d5792", "pc05", -1},     // seria rozpoznania (pc06 – 3 narzędzia)
		{"736fe6af-3ac1-4c08-b5df-5bb62a26c9b1", "pc05,pc07", 3}, // AD: nltest, net group, AdFind
		{"94fed0e6-7f25-4dca-8b36-0a388ca470b1", "srv02/BTOBTO,srv02/PSEXESVC", 2},
		{"65eed598-2db0-432e-9dd4-6bbeaf1f556e", "srv02,srv03", 2}, // WMI i WinRM
		{"6544f35a-30f7-4657-a686-fca254feeb5f", "ws00/svc-x,ws01/svc-x,ws02/svc-x,ws03/svc-x,ws04/svc-x", 5},
		{"b4ee06e9-dd71-4185-8f9e-4b8b76f8528a", "pc08", 1},          // zrzut ekranu
		{"e7792889-bce8-4541-b87c-df1cd6e7eff3", "pc08", 1},          // 7z a -p
		{"45f1f0fb-8052-4bf6-b3d3-fb05a6117cf0", "pc09", 2},          // certutil, bitsadmin
		{"dc417c4c-fd8e-4e9f-8967-997dc4295798", "pc09", 2},          // AnyDesk, plink -R
		{"dccb69cd-3a68-4712-aee5-9087e23f9de8", "pc10", 2},          // rclone copy, curl -T
		{"c443836f-8cb9-4a07-a788-12ab3b6a17e8", "203.0.113.77", -1}, // skanowanie portów
		{"9c55e2e1-ad24-400b-9d3d-bb7159593ab4", "10.10.10.66", -1},
		{"3cd1463f-e00d-4b16-a478-06a8a67e530a", "pc11", 3}, // Defender: wykrycia (bez 1117)
		{"d83b0e53-f614-4795-b75c-ada2efd162b8", "pc12", 1}, // nieudane usunięcie
		{"558a2a89-3f7e-40b9-8ea1-9a6e36e65a55", "pc12", 1}, // wyłączona ochrona
		{"3e35fe1a-3373-4e25-9943-e757afe9f78b", "pc12", 1}, // wykluczenie (zwykła zmiana – nie)
		{"aca5ef34-394c-4242-abc1-9239e7d0b077", "pc12", 1}, // ASR  // przeszukiwanie sieci
	} {
		got := byRule[c.rule]
		if uniq(got) != c.hosts || (c.n >= 0 && len(got) != c.n) {
			t.Errorf("%s: trafienia %v (oczekiwano %s ×%d)", c.rule, got, c.hosts, c.n)
		}
	}
}
