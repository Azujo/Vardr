package decode

import (
	"strconv"
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
			e, err := Event(contract.Event{ID: "c:syslog:g0:1", Source: "syslog:udp", Raw: s, Peer: "192.168.88.1"}, "c", ingested, set, warsaw)
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
