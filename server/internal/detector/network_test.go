// SPDX-License-Identifier: AGPL-3.0-or-later

package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/internal/decode"
	"siem/internal/model"
)

// Reguły urządzeń sieciowych na zdarzeniach z prawdziwych dekoderów syslog.
func TestNetworkRules(t *testing.T) {
	warsaw, _ := time.LoadLocation("Europe/Warsaw")
	ds, err := decode.Builtin(warsaw)
	if err != nil {
		t.Fatal(err)
	}
	set := decode.NewSet(ds)
	dec := func(n int, raw string) model.Event {
		e, err := decode.Event(contract.Event{ID: fmt.Sprintf("c:syslog:g0:%d", n), Raw: raw, Peer: "192.168.88.1"},
			"c", t0, set, warsaw)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	cases := []struct {
		rule, line string
		count      int
	}{
		{"cb8df317-c73f-45ef-ae1f-22758105458c", // MikroTik, RouterOS 7
			"<131>Oct  9 13:%02d:%02d MikroTik login failure for user admin from 203.0.113.9 via winbox", 5},
		{"fe9a7cec-b4c5-4314-b533-580e364ba472", // FortiGate SSL VPN
			`<189>date=2026-10-09 time=13:%02d:%02d devname="FGT-HQ" tz="+0200" logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" remip=198.51.100.20 user="user{n}" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"`, 10},
		{"2e43f8f5-104d-4f1f-8523-bf57f16a3d1b", // FortiGate administrator
			`<189>date=2026-10-09 time=13:%02d:%02d devname="FGT-HQ" tz="+0200" logid="0100032002" type="event" subtype="system" user="admin" srcip=198.51.100.7 action="login" status="failed" msg="Administrator admin login failed"`, 5},
	}
	for _, c := range cases {
		e := repoEngine(t)
		var evs []model.Event
		for i := range c.count {
			evs = append(evs, dec(i, strings.ReplaceAll(fmt.Sprintf(c.line, 1, i*5), "{n}", fmt.Sprint(i))))
		}
		if h, _ := run(e, c.rule, evs[:c.count-1]...); len(h) != 0 {
			t.Fatalf("%s: poniżej progu %d trafień", c.rule, len(h))
		}
		h, _ := run(e, c.rule, evs[c.count-1])
		if len(h) != c.count {
			t.Fatalf("%s: próg – %d trafień, oczekiwano %d (zdarzenie %+v)", c.rule, len(h), c.count, evs[0])
		}
	}
	// Udane logowanie do routera nie liczy się do serii.
	ok := dec(99, "<134>Oct  9 13:01:00 MikroTik user admin logged in from 203.0.113.9 via winbox")
	if h, _ := run(repoEngine(t), "cb8df317-c73f-45ef-ae1f-22758105458c", ok, ok, ok, ok, ok); len(h) != 0 {
		t.Fatal("udane logowania nie powinny dawać alertu")
	}
}
