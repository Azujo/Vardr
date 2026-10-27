// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
)

var (
	warsaw, _ = time.LoadLocation("Europe/Warsaw")
	ingested  = time.Date(2026, 10, 9, 11, 30, 0, 0, time.UTC)
)

func builtinSet(t *testing.T) *Set {
	t.Helper()
	ds, err := Builtin(warsaw)
	if err != nil {
		t.Fatal(err)
	}
	return NewSet(ds)
}

func TestParseHeader(t *testing.T) {
	cases := []struct {
		raw                     string
		format, host, app, msg  string
		sev                     int
		year, hour, min, offset int
	}{
		{"<134>Oct  9 13:24:55 MikroTik system,info,account user admin logged in", "rfc3164", "MikroTik",
			"system,info,account", "user admin logged in", 6, 2026, 11, 24, 0},
		{"<86>Oct  9 13:24:55 host sshd[1234]: Failed password for root", "rfc3164", "host", "sshd",
			"Failed password for root", 6, 2026, 11, 24, 0},
		{"<165>1 2026-10-09T13:00:00.123+02:00 fw01 app 77 ID47 [ex@32473 a=\"b]\"] Hello world", "rfc5424", "fw01", "app",
			"Hello world", 5, 2026, 11, 0, 0},
		{"<189>date=2026-10-09 time=13:05:12 devname=\"FGT\" logid=\"0101039426\"", "bare", "", "",
			"date=2026-10-09 time=13:05:12 devname=\"FGT\" logid=\"0101039426\"", 5, 0, 0, 0, 0},
	}
	for i, c := range cases {
		h := ParseHeader(c.raw, warsaw, ingested)
		if h.Format != c.format || h.Host != c.host || h.App != c.app || h.Message != c.msg || h.Severity != c.sev {
			t.Errorf("przypadek %d: %+v", i, h)
			continue
		}
		if c.year != 0 {
			u := h.Time.UTC()
			if u.Year() != c.year || u.Hour() != c.hour || u.Minute() != c.min {
				t.Errorf("przypadek %d: czas %s", i, h.Time)
			}
		}
	}
	// Grudzień odebrany w styczniu – poprzedni rok.
	h := ParseHeader("<13>Dec 31 23:59:00 h a: x", warsaw, time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC))
	if h.Time.Year() != 2026 {
		t.Fatalf("przełom roku: %s", h.Time)
	}
}

func TestBuiltinSamples(t *testing.T) {
	ds, err := Builtin(warsaw)
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet(ds)
	for _, d := range ds {
		if len(d.Samples) == 0 {
			t.Errorf("%s: brak próbek", d.ID)
		}
		for i, s := range d.Samples {
			e, err := Event(contract.Event{ID: "c:syslog:g0:1", Source: d.SampleSource(), Raw: s, Peer: "192.168.88.1"}, "c", ingested, set, warsaw)
			if err != nil || e.Fields["decoder.id"] != d.ID || e.Fields["decoder.pattern"] == "none" {
				t.Errorf("%s próbka %d: dekoder %q, wzorzec %q, błąd %v", d.ID, i, e.Fields["decoder.id"], e.Fields["decoder.pattern"], err)
			}
		}
	}
}

func TestFortiGate(t *testing.T) {
	set := builtinSet(t)
	dec := func(raw string) map[string]string {
		e, err := Event(contract.Event{ID: "c:syslog:g0:1", Raw: raw, Peer: "10.0.0.1"}, "c", ingested, set, warsaw)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"dataset": e.Dataset, "host": e.HostName, "user": e.UserName, "ip": e.SourceIP,
			"action": e.Action, "outcome": e.Outcome, "code": itoa(e.Code), "time": e.Timestamp.Format(time.RFC3339),
			"tq": e.TimeQuality, "msg": e.Message, "reason": e.Fields["reason"], "provider": e.Provider}
	}
	vpn := dec(builtin(t, "fortigate", 0))
	want := map[string]string{"dataset": "fortinet.fortigate", "host": "fgt-hq", "user": "jkowalski", "ip": "203.0.113.45",
		"action": "ssl-login-fail", "outcome": "failure", "code": "101039426", "time": "2026-10-09T11:05:12Z",
		"reason": "sslvpn_login_permission_denied", "msg": "SSL user failed to logged in", "provider": "event"}
	for k, v := range want {
		if vpn[k] != v {
			t.Errorf("VPN %s: %q, oczekiwano %q", k, vpn[k], v)
		}
	}
	if adm := dec(builtin(t, "fortigate", 1)); adm["outcome"] != "failure" || adm["user"] != "admin" || adm["ip"] != "198.51.100.7" {
		t.Errorf("logowanie administratora: %v", adm)
	}
	if tr := dec(builtin(t, "fortigate", 2)); tr["outcome"] != "success" || tr["ip"] != "192.168.1.10" || tr["provider"] != "traffic" {
		t.Errorf("ruch: %v", tr)
	}
}

func TestMikroTik(t *testing.T) {
	set := builtinSet(t)
	for i, want := range []map[string]string{
		{"action": "login", "outcome": "failure", "user": "admin", "ip": "192.168.88.10", "proc": "ssh"},
		{"action": "login", "outcome": "success", "user": "admin", "ip": "192.168.88.10", "proc": "winbox"},
		{"action": "dhcp-lease", "client_ip": "192.168.88.254", "client_host": "iPhone"},
		{"action": "firewall", "ip": "203.0.113.9", "dst_port": "22", "fw_prefix": "DROP-WAN"},
		{"action": "config-change", "user": "admin", "ip": "192.168.88.10", "change": "added"},
		// RouterOS 7: bez tematów w nagłówku.
		{"action": "login", "outcome": "failure", "user": "admin", "ip": "192.168.88.10", "proc": "winbox"},
		{"action": "login", "outcome": "success", "user": "admin", "ip": "192.168.88.10", "proc": "winbox"},
		{"action": "wifi-association", "client_mac": "8C:85:90:12:34:56", "interface": "wifi3", "ssid": "MikroTik-Guest", "wifi_action": "connected"},
		{"action": "clock-change", "time_source": "cloud"},
		{"action": "link-change", "interface": "ether4", "link": "down"},
	} {
		e, err := Event(contract.Event{ID: "c:syslog:g0:1", Raw: builtin(t, "mikrotik", i), Peer: "192.168.88.1"}, "c", ingested, set, warsaw)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{"action": e.Action, "outcome": e.Outcome, "user": e.UserName, "ip": e.SourceIP, "proc": e.ProcessName}
		for k, v := range e.Fields {
			if _, ok := got[k]; !ok {
				got[k] = v
			}
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("MikroTik %d %s: %q, oczekiwano %q", i, k, got[k], v)
			}
		}
		if e.HostName != "mikrotik" || e.Dataset != "mikrotik.routeros" {
			t.Errorf("MikroTik %d: host %q dataset %q", i, e.HostName, e.Dataset)
		}
	}
}

// Router o zmienionej tożsamości (RouterOS 7, bez tematów): logowania
// rozpoznane po treści, reszta – ogólny syslog; inne urządzenia bez zmian.
func TestMikroTikRenamed(t *testing.T) {
	set := builtinSet(t)
	for raw, want := range map[string]string{
		"<131>Oct  9 20:54:15 gw-hq login failure for user admin from 10.1.1.5 via ssh": "mikrotik.routeros",
		"<134>Oct  9 20:54:15 gw-hq user jan logged out from 10.1.1.5 via winbox":       "mikrotik.routeros",
		"<134>Oct  9 20:50:04 gw-hq ether4 link down":                                   "syslog.generic",
		"<13>Oct  9 20:50:04 nas01 user jan logged in":                                  "syslog.generic",
	} {
		e, err := Event(contract.Event{ID: "x", Raw: raw, Peer: "10.1.1.1"}, "c", ingested, set, warsaw)
		if err != nil || e.Dataset != want {
			t.Errorf("%q: %s, oczekiwano %s (%v)", raw, e.Dataset, want, err)
		}
	}
	if h := ParseHeader("<134>Oct  9 20:54:15 gw-hq user jan logged out", warsaw, ingested); h.App != "" || h.Message != "user jan logged out" {
		t.Errorf("znacznik bez dwukropka i przecinka: %+v", h)
	}
}

func TestGenericAndErrors(t *testing.T) {
	set := builtinSet(t)
	e, err := Event(contract.Event{ID: "c:syslog:g0:1", Raw: "<13>Oct  9 13:00:00 nas01 smbd[22]: share opened", Peer: "192.168.88.180"},
		"c", ingested, set, warsaw)
	if err != nil || e.Dataset != "syslog.generic" || e.HostName != "nas01" || e.Provider != "smbd" || e.Message != "share opened" {
		t.Fatalf("ogólny syslog: %+v %v", e, err)
	}
	if e, _ := Event(contract.Event{ID: "x", Raw: "bez nagłówka", Peer: "10.1.1.1"}, "c", ingested, set, warsaw); e.HostName != "10.1.1.1" || e.TimeQuality != "missing" {
		t.Fatalf("bez nagłówka: host %q, czas %q", e.HostName, e.TimeQuality)
	}
	jd, err := Parse([]byte("id: app-json\ntitle: App\ndataset: app.json\nmatch:\n  app: [myapp]\nparser:\n  type: json\nfields:\n  user.name: actor.name\n"), warsaw)
	if err != nil {
		t.Fatal(err)
	}
	js := NewSet([]*Decoder{jd})
	if e, err := Event(contract.Event{ID: "x", Raw: `<14>Oct  9 13:00:00 h myapp: {"actor":{"name":"ewa"},"ok":true}`}, "c", ingested, js, warsaw); err != nil || e.UserName != "ewa" || e.Fields["ok"] != "true" {
		t.Fatalf("JSON: %+v %v", e, err)
	}
	if _, err := Event(contract.Event{ID: "x", Raw: `<14>Oct  9 13:00:00 h myapp: {zepsuty`}, "c", ingested, js, warsaw); err == nil {
		t.Fatal("zepsuty JSON powinien trafić do kwarantanny")
	}
	for name, y := range map[string]string{
		"brak match":  "id: a1\ntitle: t\ndataset: d.x\nparser:\n  type: kv\n",
		"zły parser":  "id: a1\ntitle: t\ndataset: d.x\nmatch:\n  app: [x]\nparser:\n  type: xml\n",
		"zły regex":   "id: a1\ntitle: t\ndataset: d.x\nmatch:\n  regex: '(('\nparser:\n  type: kv\n",
		"nieznane":    "id: a1\ntitle: t\ndataset: d.x\nmatch:\n  app: [x]\nparser:\n  type: kv\nfoo: 1\n",
		"csv bez kol": "id: a1\ntitle: t\ndataset: d.x\nmatch:\n  app: [x]\nparser:\n  type: csv\n",
	} {
		if _, err := Parse([]byte(y), warsaw); err == nil {
			t.Errorf("%s: definicja powinna zostać odrzucona", name)
		}
	}
}

func TestKV(t *testing.T) {
	m := map[string]string{}
	parseKV(`a=1 b="x y" c="z \"q\"" d= e=end`, m)
	if m["a"] != "1" || m["b"] != "x y" || m["c"] != `z "q"` || m["d"] != "" || m["e"] != "end" {
		t.Fatalf("kv: %v", m)
	}
}

func builtin(t *testing.T, id string, i int) string {
	t.Helper()
	ds, _ := Builtin(warsaw)
	for _, d := range ds {
		if d.ID == id {
			return d.Samples[i]
		}
	}
	t.Fatalf("brak dekodera %s", id)
	return ""
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func TestMerge(t *testing.T) {
	ds, _ := Builtin(warsaw)
	fg := BuiltinSources()["fortigate"]
	mine := strings.Replace(fg, "dataset: fortinet.fortigate", "dataset: fortinet.custom", 1)
	set, errs := Merge(ds, map[string]Custom{
		"fortigate": {Source: mine, Enabled: true},                                                // zastąpiony
		"mikrotik":  {Enabled: false},                                                             // wyłączony
		"zly":       {Source: "id: zly\n", Enabled: true},                                         // błąd – pominięty
		"inny-id":   {Source: strings.Replace(mine, "id: fortigate", "id: x1", 1), Enabled: true}, // id ≠ klucz
	}, warsaw)
	if len(errs) != 2 {
		t.Fatalf("błędy: %v", errs)
	}
	got := map[string]string{}
	for _, d := range set.List() {
		got[d.ID] = d.Dataset
	}
	if got["fortigate"] != "fortinet.custom" || got["mikrotik"] != "" || got["zly"] != "" || got["x1"] != "" || len(got) != len(ds)-1 {
		t.Fatalf("zestaw: %v", got)
	}
	for _, d := range ds {
		if err := d.CheckSamples(ingested); err != nil {
			t.Errorf("%s: %v", d.ID, err)
		}
	}
	peerOnly, err := Parse([]byte("id: p1\ntitle: t\ndataset: d.x\nmatch:\n  peer: [10.9.0.0/16]\nparser:\n  type: kv\nsamples:\n  - '<13>a=1'\n"), warsaw)
	if err != nil || peerOnly.CheckSamples(ingested) != nil {
		t.Fatalf("próbka dekodera z warunkiem peer: %v %v", err, peerOnly.CheckSamples(ingested))
	}
}

// Logowania i zmiany w katalogu Entra ID (rekordy z konektora API).
func TestEntra(t *testing.T) {
	set := builtinSet(t)
	e, err := Event(contract.Event{ID: "conn:entra-signin:k:1", Source: "entra:signin", Raw: builtin(t, "entra-signin", 0)}, "conn", ingested, set, warsaw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "azure.signinlogs" || e.UserName != "jkowalski@azujo.pl" || e.SourceIP != "185.220.101.7" || e.Outcome != "failure" ||
		e.Code != 50126 || e.Action != "sign-in" || e.HostName != "entra-id" || e.Fields["source.geo.country_iso_code"] != "NL" ||
		e.Fields["user_agent.client"] != "IMAP4" || e.Timestamp.Format(time.RFC3339) != "2026-10-12T09:58:00Z" || e.Parser != APIParserVersion ||
		e.Fields["syslog.peer"] != "" || e.Fields["event.source"] != "entra:signin" || !strings.HasPrefix(e.Message, "Error validating") {
		t.Fatalf("logowanie Entra: %+v", e)
	}
	ok, err := Event(contract.Event{ID: "x", Source: "entra:signin", Raw: builtin(t, "entra-signin", 1)}, "conn", ingested, set, warsaw)
	if err != nil || ok.Outcome != "success" || ok.HostName != "desktop-ano" || ok.Code != 0 {
		t.Fatalf("udane logowanie: %+v %v", ok, err)
	}
	a, err := Event(contract.Event{ID: "y", Source: "entra:audit", Raw: builtin(t, "entra-audit", 0)}, "conn", ingested, set, warsaw)
	if err != nil || a.Dataset != "azure.auditlogs" || a.Action != "Add member to role" || a.UserName != "heimdall-lab@azujo.pl" ||
		a.Fields["user.target.name"] != "jkowalski@azujo.pl" || !strings.Contains(a.Fields["azure.role"], "Global Administrator") || a.Outcome != "success" {
		t.Fatalf("zmiana w katalogu: %+v %v", a, err)
	}
	// Źródło API bez dekodera – kwarantanna (nie syslog.generic).
	if _, err := Event(contract.Event{ID: "z", Source: "entra:nowe", Raw: "{}"}, "conn", ingested, set, warsaw); err == nil {
		t.Fatal("źródło API bez dekodera powinno trafić do kwarantanny")
	}
}

// Nowe źródła syslog (1.6.2): pola z próbek wbudowanych dekoderów.
func TestSyslogSources(t *testing.T) {
	set := builtinSet(t)
	check := func(id string, i int, dataset string, want map[string]string) {
		t.Helper()
		e, err := Event(contract.Event{ID: "c:syslog:g0:1", Raw: builtin(t, id, i), Peer: "192.168.1.1"}, "c", ingested, set, warsaw)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{"action": e.Action, "outcome": e.Outcome, "user": e.UserName, "ip": e.SourceIP, "proc": e.ProcessName,
			"cmd": e.CommandLine, "code": itoa(e.Code), "host": e.HostName, "time": e.Timestamp.Format(time.RFC3339)}
		for k, v := range e.Fields {
			if _, ok := got[k]; !ok {
				got[k] = v
			}
		}
		if e.Dataset != dataset {
			t.Errorf("%s %d: zbiór %q, oczekiwano %q", id, i, e.Dataset, dataset)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s %d %s: %q, oczekiwano %q", id, i, k, got[k], v)
			}
		}
	}
	for i, want := range []map[string]string{
		{"action": "login", "outcome": "failure", "user": "oracle", "ip": "203.0.113.9", "invalid_user": "true", "proc": "password", "host": "web01"},
		{"action": "login", "outcome": "failure", "user": "root", "ip": "203.0.113.9"},
		{"action": "login", "outcome": "success", "user": "jan", "ip": "192.168.1.5", "proc": "publickey"},
		{"action": "invalid-user", "user": "admin", "ip": "203.0.113.9"},
		{"action": "sudo", "outcome": "success", "user": "jan", "target_user": "root", "cmd": "/usr/bin/apt update"},
		{"action": "sudo", "outcome": "failure", "user": "ewa", "sudo_error": "3 incorrect password attempts", "cmd": "/bin/bash"},
		{"action": "su", "outcome": "success", "user": "jan", "target_user": "root"},
		{"action": "auth-failure", "outcome": "failure", "user": "root", "pam_service": "su", "ruser": "ewa"},
		{"action": "user-created", "target_user": "backdoor", "uid": "1002", "shell": "/bin/bash"},
		{"action": "group-member-added", "target_user": "backdoor", "group": "sudo"},
		{"action": "user-deleted", "target_user": "backdoor"},
		{"action": "password-change", "target_user": "jan"},
		{"action": "session-open", "user": "jan", "session": "42"},
	} {
		check("linux", i, "linux.auth", want)
	}
	for i, want := range []map[string]string{
		{"action": "firewall", "outcome": "failure", "fw_action": "block", "ip": "203.0.113.9", "dst_ip": "192.168.1.10", "dst_port": "22", "proto": "tcp", "interface": "igb0", "direction": "in"},
		{"action": "firewall", "outcome": "success", "ip": "192.168.1.10", "dst_ip": "9.9.9.9", "dst_port": "53", "proto": "udp", "host": "opnsense.local"},
		{"action": "firewall", "outcome": "failure", "ip": "2001:db8::9", "dst_port": "443", "ip_version": "6"},
		{"action": "login", "outcome": "failure", "user": "admin", "ip": "203.0.113.9", "proc": "webgui"},
		{"action": "login", "outcome": "success", "user": "admin", "ip": "192.168.1.5"},
	} {
		check("pfsense", i, "pfsense.firewall", want)
	}
	for i, want := range []map[string]string{
		{"action": "firewall", "outcome": "failure", "code": "106023", "ip": "203.0.113.9", "dst_port": "22", "acl": "OUTSIDE_IN", "host": "asa01"},
		{"action": "firewall", "outcome": "success", "code": "106100", "ip": "198.51.100.7", "dst_ip": "192.168.1.20", "dst_port": "443"},
		{"action": "login", "outcome": "failure", "code": "605004", "user": "admin", "ip": "203.0.113.9", "proc": "ssh", "time": "2026-10-09T11:00:02Z"},
		{"action": "login", "outcome": "success", "code": "605005", "user": "admin", "ip": "192.168.1.5"},
		{"action": "login", "outcome": "failure", "code": "113005", "user": "jkowalski", "ip": "203.0.113.45", "reason": "AAA failure", "proc": "vpn"},
		{"action": "vpn-connect", "outcome": "success", "user": "jkowalski", "ip": "203.0.113.45", "group_policy": "GP-VPN"},
		{"action": "config-change", "user": "admin", "cmd": "access-list OUTSIDE_IN extended permit tcp any any eq 3389"},
		{"action": "other", "code": "302013", "host": "192.168.1.1"},
	} {
		check("cisco-asa", i, "cisco.asa", want)
	}
}

func TestIIS(t *testing.T) {
	set := builtinSet(t)
	ingested := time.Date(2026, 10, 27, 10, 5, 0, 0, time.UTC)
	e, err := Event(contract.Event{ID: "a:iis:W3SVC1:g0:1", Source: "file:iis", Raw: builtin(t, "iis", 0)}, "a", ingested, set, warsaw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "iis.access" || e.HostName != "srv-www" || e.SourceIP != "203.0.113.7" || e.Outcome != "failure" ||
		e.Action != "http-request" || e.Message != "/owa/auth.owa" || e.Fields["cs-method"] != "POST" ||
		e.Fields["http.response.status_code"] != "401" || e.Fields["iis.site"] != "W3SVC1" ||
		!e.Timestamp.Equal(time.Date(2026, 10, 27, 10, 0, 2, 0, time.UTC)) || e.Fields["syslog.peer"] != "" {
		t.Fatalf("%+v", e)
	}
	ok, err := Event(contract.Event{ID: "x", Source: "file:iis", Raw: builtin(t, "iis", 1)}, "a", ingested, set, warsaw)
	if err != nil || ok.Outcome != "success" || ok.UserDomain != "AZUJO" || ok.UserName != "jkowalski" || ok.Fields["url.query"] != "id=7" {
		t.Fatalf("%+v %v", ok, err)
	}
}
