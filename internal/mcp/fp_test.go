// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import "testing"

// Kandydaci na wyjątki: tylko fałszywe alarmy i uzasadnione działania,
// grupy po regule, najczęstsze wartości, najwięcej alertów pierwsze.
func TestFPGroup(t *testing.T) {
	got := fpGroup([]fpAlert{
		{ID: 1, RuleID: "a", Resolution: "false_positive", HostName: "SRV1", UserName: "svc_backup", Hits: 3, Reason: "kopia"},
		{ID: 2, RuleID: "a", Resolution: "benign", HostName: "SRV1", UserName: "SVC_BACKUP", Hits: 2, Reason: "kopia"},
		{ID: 3, RuleID: "a", Resolution: "false_positive", HostName: "SRV2", UserName: "svc_backup", Hits: 1},
		{ID: 4, RuleID: "b", Resolution: "false_positive", HostName: "PC1"},
		{ID: 5, RuleID: "c", Resolution: "true_positive", HostName: "PC1"},
		{ID: 6, RuleID: "c", Resolution: ""},
	})
	if len(got) != 2 || got[0].RuleID != "a" || got[1].RuleID != "b" {
		t.Fatalf("grupy: %+v", got)
	}
	a := got[0]
	if a.FalsePositive != 2 || a.Benign != 1 || a.Hits != 6 || len(a.SampleAlerts) != 3 {
		t.Fatalf("reguła a: %+v", a)
	}
	if a.TopHosts[0] != (fpValue{"SRV1", 2}) || a.TopUsers[0] != (fpValue{"svc_backup", 3}) || len(a.CloseReasons) != 1 {
		t.Fatalf("wartości: %+v %+v %v", a.TopHosts, a.TopUsers, a.CloseReasons)
	}
}
