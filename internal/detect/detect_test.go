package detect

import (
	"strings"
	"testing"

	"siem/internal/model"
)

func ev(channel string, code uint32, fields map[string]string) Event {
	f := map[string]string{"winlog.channel": channel}
	for k, v := range fields {
		f[k] = v
	}
	return Event{&model.Event{Code: code, HostName: "dc01.lab.local", Fields: f, Dataset: "windows." + strings.ToLower(channel)}}
}

func mustRule(t *testing.T, y string) *Rule {
	t.Helper()
	r, err := Parse([]byte(y), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const head = "title: t\nid: test-rule\nlevel: low\nlogsource:\n  product: windows\n"

func TestModifiersAndConditions(t *testing.T) {
	r := mustRule(t, head+`  service: security
detection:
  sel_a:
    EventID: [4625, 4771]
    TargetUserName|startswith: 'adm'
  sel_b:
    IpAddress|cidr: '10.0.0.0/8'
  filter:
    TargetUserName|endswith: '$'
  condition: 1 of sel_* and not filter
`)
	cases := []struct {
		e    Event
		want bool
	}{
		{ev("Security", 4625, map[string]string{"TargetUserName": "ADMIN", "IpAddress": "192.168.1.1"}), true},
		{ev("Security", 4624, map[string]string{"TargetUserName": "x", "IpAddress": "::ffff:10.1.2.3"}), true},
		{ev("Security", 4624, map[string]string{"TargetUserName": "PC01$", "IpAddress": "10.1.2.3"}), false},
		{ev("System", 4625, map[string]string{"TargetUserName": "admin"}), false}, // inny kanał
		{ev("Security", 4624, map[string]string{"TargetUserName": "jan"}), false},
	}
	for i, c := range cases {
		if got := r.Match(c.e); got != c.want {
			t.Errorf("przypadek %d: %v, oczekiwano %v", i, got, c.want)
		}
	}
}

func TestWildcardsAndAliases(t *testing.T) {
	r := mustRule(t, head+`  category: process_creation
detection:
  selection:
    Image: '*\cmd.exe'
    CommandLine|contains|all: ['whoami', '/groups']
  condition: selection
`)
	sysmon := ev("Microsoft-Windows-Sysmon/Operational", 1, map[string]string{"Image": `C:\Windows\System32\CMD.EXE`, "CommandLine": "cmd /c whoami /groups"})
	sec := ev("Security", 4688, map[string]string{"NewProcessName": `C:\Windows\System32\cmd.exe`, "CommandLine": "whoami /groups"})
	other := ev("Security", 4688, map[string]string{"NewProcessName": `C:\Windows\System32\cmd.exe`, "CommandLine": "whoami"})
	if !r.Match(sysmon) || !r.Match(sec) || r.Match(other) {
		t.Fatal("process_creation: Sysmon 1 i Security 4688 (alias NewProcessName), contains|all")
	}
	for pat, s := range map[string]string{`c:\a\\*.exe`: `c:\a\b.exe`, `a?c`: "abc", `*x*y`: "zzxzzy", `lit\*`: "lit*"} {
		if !wildcard(pat, s) {
			t.Errorf("%q nie pasuje do %q", pat, s)
		}
	}
	if wildcard(`lit\*`, "litx") || wildcard("a?c", "ac") || wildcard("*.exe", "a.exe.txt") {
		t.Error("maski: nadmiarowe dopasowanie")
	}
}

func TestRejectsUnsupported(t *testing.T) {
	for name, y := range map[string]string{
		"agregacja":     head + "detection:\n  s:\n    EventID: 1\n  condition: s | count() > 5\n",
		"modyfikator":   head + "detection:\n  s:\n    CommandLine|base64offset|contains: x\n  condition: s\n",
		"kategoria":     "title: t\nid: test-rule\nlevel: low\nlogsource:\n  category: image_load\ndetection:\n  s:\n    EventID: 1\n  condition: s\n",
		"brak selekcji": head + "detection:\n  s:\n    EventID: 1\n  condition: s and x\n",
		"zły poziom":    "title: t\nid: test-rule\nlevel: urgent\nlogsource:\n  product: windows\ndetection:\n  s:\n    EventID: 1\n  condition: s\n",
		"nieznane pole": head + "unknown: 1\ndetection:\n  s:\n    EventID: 1\n  condition: s\n",
	} {
		if _, err := Parse([]byte(y), "x.yml"); err == nil {
			t.Errorf("%s: reguła powinna zostać odrzucona", name)
		}
	}
}

// Reguły z repozytorium (rules/) muszą się kompilować i wykrywać swoje scenariusze.
func TestRepositoryRules(t *testing.T) {
	rules, errs, err := LoadDir("../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatalf("reguły z repozytorium: %v %+v", err, errs)
	}
	byID := map[string]*Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	must := func(id string, e Event, want bool) {
		t.Helper()
		r := byID[id]
		if r == nil {
			t.Fatalf("brak reguły %s", id)
		}
		if got := r.Match(e); got != want {
			t.Errorf("%s (%s): %v, oczekiwano %v", r.Title, id, got, want)
		}
	}
	// Dodanie do Backup Operators (lokalna grupa domeny, SID wbudowany) – i do zwykłej grupy.
	must("f406b909-37ba-4b21-b8c2-f4bd5cbf3192", ev("Security", 4732, map[string]string{"TargetSid": "S-1-5-32-551", "TargetUserName": "Backup Operators"}), true)
	must("f406b909-37ba-4b21-b8c2-f4bd5cbf3192", ev("Security", 4728, map[string]string{"TargetSid": "S-1-5-21-1-2-3-512"}), true)
	must("f406b909-37ba-4b21-b8c2-f4bd5cbf3192", ev("Security", 4728, map[string]string{"TargetSid": "S-1-5-21-1-2-3-1105"}), false)
	must("557f7b4d-d6bf-4d17-8aaf-cd1094a46a67", ev("Security", 1102, nil), true)
	enc := ev("Security", 4688, map[string]string{"NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine": `powershell -NoProfile -EncodedCommand VwByAGkAdABlAA==`})
	must("4b767c65-adff-4033-841f-3a325dc1bda4", enc, true)
	plain := ev("Security", 4688, map[string]string{"NewProcessName": `C:\x\powershell.exe`, "CommandLine": `powershell -ExecutionPolicy Bypass -File x.ps1`})
	must("4b767c65-adff-4033-841f-3a325dc1bda4", plain, false)
	must("3a480a5a-0ee4-4835-8c79-62f868ca9498", ev("Microsoft-Windows-PowerShell/Operational", 4104,
		map[string]string{"ScriptBlockText": "'heimdall-test VirtualAlloc'"}), true)
	must("3a480a5a-0ee4-4835-8c79-62f868ca9498", ev("Microsoft-Windows-PowerShell/Operational", 4104,
		map[string]string{"ScriptBlockText": "(New-Object Net.WebClient).DownloadFile('x','y')"}), false)
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `C:\Users\jan\AppData\Local\Temp\svc.exe`}), true)
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `"C:\Program Files\Vendor\svc.exe"`}), false)
	// Fałszywe alarmy z laboratorium: agent SIEM (konfiguracja w ProgramData) i aktualizacje Defendera.
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `"C:\Program Files\SiemAgent\siem_agent.exe" -config C:\ProgramData\SiemAgent\agent.yaml`}), false)
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{3AD4}\MpKslDrv.sys`}), false)
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `"C:\Program Files\PowerShell\7\pwsh.exe" -c iex(x) C:\Users\a\x.ps1`}), true)
	must("7ea5663e-c655-439a-a894-616ba1e203d6", ev("System", 7045, map[string]string{"ImagePath": `C:\ProgramData\updater\svc.exe`}), true)
	must("9f379649-a04b-43de-b3a0-25587cf713de", ev("Security", 4720, nil), true)
	cleared := ev("System", 104, nil)
	cleared.Provider = "Microsoft-Windows-Eventlog"
	must("f4edfeeb-bfc1-43b9-91e1-1bbfe1c8a7a9", cleared, true)
	must("f4edfeeb-bfc1-43b9-91e1-1bbfe1c8a7a9", ev("System", 104, nil), false)
	svc := "d6db3a52-6c0f-477f-b079-66457370158a"
	must(svc, ev("System", 7036, map[string]string{"param1": "SIEM Agent", "param2": "stopped"}), false) // reguła wbudowana „sabotaż agenta”
	must(svc, ev("System", 7036, map[string]string{"param1": "Sysmon64", "param2": "zatrzymany"}), true)
	must(svc, ev("System", 7036, map[string]string{"param1": "SIEM Agent", "param2": "running"}), false)
	must(svc, ev("System", 7034, map[string]string{"param1": "Sysmon"}), true)
	must(svc, ev("System", 7036, map[string]string{"param1": "Spooler", "param2": "stopped"}), false)

	if k := byID["4b767c65-adff-4033-841f-3a325dc1bda4"].GroupKey(enc); len(k) != 2 || k[0] != "dc01.lab.local" || !strings.Contains(k[1], "encodedcommand") {
		t.Fatalf("klucz alertu: %v", k)
	}
}

func TestRenderInstructions(t *testing.T) {
	e := ev("Security", 4720, map[string]string{"TargetUserName": "jan", "SubjectUserName": "admin", "SubjectDomainName": "LAB"})
	got := Render(`{{SubjectDomainName}}\{{ SubjectUserName }} założył {{TargetUserName}} na {{Computer}}; {{Brak}}`, e)
	if got != `LAB\admin założył jan na dc01.lab.local; (brak)` {
		t.Fatalf("Render: %q", got)
	}
}

func TestUnwrap(t *testing.T) {
	in := "Zdekoduj parametr i oceń skrypt.\nUruchomienie z Office jest\nbardzo podejrzane.\n\nDrugi akapit:\n- punkt pierwszy\n- punkt drugi\n"
	want := "Zdekoduj parametr i oceń skrypt. Uruchomienie z Office jest bardzo podejrzane.\n\nDrugi akapit:\n- punkt pierwszy\n- punkt drugi"
	if got := Unwrap(in); got != want {
		t.Fatalf("Unwrap:\n%q\n%q", got, want)
	}
}

// Produkt → zbiór danych: rodzina zbioru, bez sklejania nazw (przegląd etapu 6).
func TestProductDataset(t *testing.T) {
	r := mustRule(t, "title: t\nid: test-rule\nlevel: low\nlogsource:\n  product: fortigate\ndetection:\n  s:\n    event.action: x\n  condition: s\n")
	for ds, want := range map[string]bool{"fortinet.fortigate": true, "fortinet.fortigate.vpn": true, "fortinet.fortigatex": false, "windows.security": false} {
		e := Event{&model.Event{Dataset: ds, Action: "x"}}
		if r.Match(e) != want {
			t.Errorf("%s: oczekiwano %v", ds, want)
		}
	}
	if sql := r.SQL(); !strings.Contains(sql, "event_dataset = 'fortinet.fortigate'") || !strings.Contains(sql, "startsWith(event_dataset, 'fortinet.fortigate.')") {
		t.Fatalf("SQL: %s", sql)
	}
}
