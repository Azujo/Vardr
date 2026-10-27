// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Korelacja: wspólny komputer i konto łączą alerty w grupę (także
// pośrednio), konta systemowe nie łączą, cecha obecna wszędzie trafia do
// common_entities, reguła na wielu komputerach – do same_rule_many_hosts.
func TestCorrelate(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)
	al := func(id int64, rule, level, host, user, ip string) corrAlert {
		return corrAlert{ID: id, RuleTitle: rule, Level: level, HostName: host, UserName: user, SourceIP: ip,
			FirstSeen: t0.Add(time.Duration(id) * time.Minute), LastSeen: t0.Add(time.Duration(id) * time.Hour)}
	}
	list := []corrAlert{
		al(1, "Brute force", "high", "PC-1", "jan", "10.0.0.9"),
		al(2, "New service", "high", "PC-1", "SYSTEM", ""),
		al(3, "VPN login from abroad", "medium", "", "Jan", "203.0.113.5"), // to samo konto co #1 (wielkość liter)
		al(4, "Brute force", "low", "PC-7", "SYSTEM", ""),                  // SYSTEM nie łączy z #2
		al(5, "Macro", "medium", "PC-8", "ewa", ""),
	}
	res := correlate(list)
	if len(res.Groups) != 1 || res.Unrelated != 2 || res.Analyzed != 5 {
		t.Fatalf("grupy: %+v", res)
	}
	g := res.Groups[0]
	ids := fmt.Sprint(g.List[0].ID, g.List[1].ID, g.List[2].ID)
	if g.Alerts != 3 || ids != "1 2 3" || !strings.Contains(strings.Join(g.Shared, ","), "host:PC-1 (2)") ||
		!strings.Contains(strings.Join(g.Shared, ","), "user:jan (2)") || g.Levels["high"] != 2 {
		t.Fatalf("grupa: %+v", g)
	}

	// Ten sam komputer w każdym z wielu alertów – nie skleja wszystkiego.
	var many []corrAlert
	for i := int64(1); i <= 30; i++ {
		many = append(many, al(i, "Rule "+fmt.Sprint(i%3), "low", fmt.Sprintf("PC-%d", i), "u"+fmt.Sprint(i), "10.0.0.1"))
	}
	res = correlate(many)
	if len(res.Groups) != 0 || len(res.Common) != 1 || !strings.HasPrefix(res.Common[0], "ip:10.0.0.1") || len(res.Spread) != 3 {
		t.Fatalf("częsta cecha: %+v", res)
	}
}
