// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/internal/decode"
	"siem/internal/identity"
	"siem/internal/reprocess"
)

// Wpis kwarantanny syslog (zepsuty JSON dla dekodera z panelu) odzyskany po
// poprawce dekodera; adres nadawcy z kwarantanny działa w warunku peer.
func TestReprocessAfterDecoderFix(t *testing.T) {
	broken := "id: app-json\ntitle: App\ndataset: app.json\nmatch:\n  peer: [10.7.0.0/16]\n  app: [myapp]\nparser:\n  type: json\n" +
		"fields:\n  user.name: actor\nsamples:\n  - '<14>Oct  9 13:00:00 h myapp: {\"actor\":\"ewa\"}'\n"
	defer SetCustom(nil)
	if _, errs := SetCustom(map[string]decode.Custom{"app-json": {Source: broken, Enabled: true}}); len(errs) > 0 {
		t.Fatal(errs)
	}
	raw := `<14>Oct  9 13:00:00 h myapp: actor=ewa ok=1`
	nb := Batch(contract.Batch{BatchID: "b", Events: []contract.Event{
		{ID: "agt-c:syslog:g0:7", Source: "syslog:udp", Raw: raw, Peer: "10.7.1.2"},
		{ID: "agt-1:System:g0:9", Source: "wineventlog:System", Raw: "<Event><System>uszkodzone"},
	}}, "agt-c", ingested)
	if len(nb.Quarantine) != 2 || nb.Quarantine[0].Peer != "10.7.1.2" {
		t.Fatalf("kwarantanna: %+v", nb.Quarantine)
	}
	// Poprawka: parser kv zamiast JSON.
	SetCustom(map[string]decode.Custom{"app-json": {Source: strings.Replace(strings.Replace(broken, "type: json", "type: kv", 1),
		`{\"actor\":\"ewa\"}`, "actor=ewa", 1), Enabled: true}})
	req := reprocess.Request{Job: 7, Chunk: 1}
	for _, q := range nb.Quarantine {
		req.Items = append(req.Items, reprocess.Item{EventID: q.EventID, AgentID: q.AgentID, Source: q.Source, Peer: q.Peer,
			Raw: q.Raw, Ingested: q.Ingested})
	}
	req.Items = append(req.Items, reprocess.Item{EventID: "x", AgentID: "agt-1", Source: "windows.security", Raw: "<Event/>"})
	now := ingested.Add(time.Hour)
	evs, rep := Reprocess(req, now)
	if len(rep.Recovered) != 1 || rep.Recovered[0] != "agt-c:syslog:g0:7" || len(rep.Failed) != 2 {
		t.Fatalf("wynik: %+v", rep)
	}
	e := evs["agt-c"][0]
	if e.Dataset != "app.json" || e.UserName != "ewa" || !e.Ingested.Equal(now) || e.Fields["siem.reprocess_job"] != "7" ||
		e.Fields["siem.quarantined_at"] != ingested.Format(time.RFC3339Nano) || e.Fields["syslog.peer"] != "10.7.1.2" {
		t.Fatalf("odzyskane zdarzenie: %+v", e)
	}
	if !strings.Contains(rep.Failed[0].Reason, "XML") || !strings.Contains(rep.Failed[1].Reason, "nie da się przetworzyć") {
		t.Fatalf("powody: %+v", rep.Failed)
	}
}

// Tożsamość osoby w zdarzeniach Windows i syslog (etap 7a).
func TestEventIdentity(t *testing.T) {
	defer identity.Set(identity.Config{})
	identity.Set(identity.Config{Domains: []string{"azujo"}, Aliases: map[string]string{"j.kowalski": "jkowalski"}})
	nb := Batch(contract.Batch{BatchID: "b", Events: []contract.Event{
		{ID: "agt-c:syslog:g0:1", Source: "syslog:udp", Peer: "10.0.0.1",
			Raw: `<189>date=2026-10-09 time=13:05:12 devname="FGT-HQ" tz="+0200" logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" remip=203.0.113.45 user="J.Kowalski"`},
		{ID: "agt-c:syslog:g0:2", Source: "syslog:udp", Peer: "10.0.0.2", Raw: "<131>Oct  9 20:54:15 MikroTik login failure for user admin from 192.168.88.10 via winbox"},
	}}, "agt-c", ingested)
	if len(nb.Events) != 2 || nb.Events[0].Identity != "jkowalski" || nb.Events[1].Identity != "admin" {
		t.Fatalf("tożsamości: %+v", nb.Events)
	}
}
