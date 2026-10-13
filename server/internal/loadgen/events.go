// Package loadgen generuje realistyczne zdarzenia Windows (XML jak z EvtRender)
// do testów obciążenia i benchmarków serwera.
package loadgen

import (
	"fmt"
	mrand "math/rand/v2"
	"time"
)

// Mieszanka zdarzeń zbliżona do stacji roboczej / serwera członkowskiego
// w domenie: głównie logowania i procesy, rzadko instalacje usług. Wagi
// w tysięcznych; udział nieudanych logowań ustawia SetFailureShare.
var mix = []struct {
	weight int
	gen    func(host string, rec uint64, t string) (channel, raw string)
}{
	{398, logon4624},
	{200, logoff4634},
	{250, process4688},
	{2, failed4625},
	{100, app1000},
	{40, system7036},
	{10, service7045},
}

const failedIdx = 3

var mixTotal = sumWeights()

func sumWeights() int {
	n := 0
	for _, m := range mix {
		n += m.weight
	}
	return n
}

// SetFailureShare ustawia udział nieudanych logowań 4625 w procentach
// (domyślnie 0,2% – zwykły dzień firmy; np. 5 = ciągły brute force na
// wszystkich kontach, scenariusz przeciążenia detekcji progowej). Różnica
// idzie z udanych logowań. Wywołać przed generowaniem zdarzeń.
func SetFailureShare(pct float64) {
	f := int(pct*10 + 0.5)
	f = max(0, min(f, mix[0].weight+mix[failedIdx].weight))
	mix[0].weight += mix[failedIdx].weight - f
	mix[failedIdx].weight = f
	mixTotal = sumWeights()
}

// RandomEvent zwraca kanał i XML losowego zdarzenia z typowej mieszanki.
func RandomEvent(host string, rec uint64, now time.Time) (string, string) {
	t := now.Format("2006-01-02T15:04:05.0000000Z")
	r := mrand.IntN(mixTotal)
	for _, m := range mix {
		if r < m.weight {
			return m.gen(host, rec, t)
		}
		r -= m.weight
	}
	return mix[0].gen(host, rec, t)
}

const sysFmt = `<System><Provider Name='%s' Guid='{%s}'/><EventID>%d</EventID><Version>%d</Version><Level>%d</Level><Task>%d</Task><Opcode>0</Opcode><Keywords>%s</Keywords><TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID><Correlation/><Execution ProcessID='%d' ThreadID='%d'/><Channel>%s</Channel><Computer>%s.lab.local</Computer><Security/></System>`

const secProvider, secGUID = "Microsoft-Windows-Security-Auditing", "54849625-5478-4994-a5ba-3e3b0328c30d"

func wrap(sys, data string) string {
	return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" + sys + data + "</Event>"
}

func secSys(id, version, task int, keywords, t string, rec uint64, host string) string {
	return fmt.Sprintf(sysFmt, secProvider, secGUID, id, version, 0, task, keywords, t, rec, 4, 1000+mrand.IntN(9000), "Security", host)
}

var users = func() []string {
	first := []string{"jan", "anna", "piotr", "katarzyna", "tomasz", "agnieszka", "marek", "ewa", "pawel", "magda"}
	last := []string{"kowalski", "nowak", "wisniewski", "wojcik", "kaminski", "lewandowski", "zielinski", "szymanski", "wozniak", "dabrowski"}
	// 3500 kont jak w firmie z roadmapy (jkowalski, jkowalski2…) – przy 100
	// kontach każde miało kilka nieudanych logowań na sekundę.
	var out []string
	for n := 1; len(out) < 3500; n++ {
		for _, f := range first {
			for _, l := range last {
				name := f[:1] + l
				if n > 1 {
					name += fmt.Sprint(n)
				}
				out = append(out, name)
			}
		}
	}
	return out
}()

var processes = []string{
	`C:\Windows\System32\svchost.exe`, `C:\Windows\explorer.exe`, `C:\Program Files\Google\Chrome\Application\chrome.exe`,
	`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	`C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE`, `C:\Windows\System32\conhost.exe`,
	`C:\Windows\System32\RuntimeBroker.exe`, `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`,
}

func user() string    { return users[mrand.IntN(len(users))] }
func logonID() string { return fmt.Sprintf("0x%x", 0x100000+mrand.IntN(0xffffff)) }
func ip() string {
	return fmt.Sprintf("10.%d.%d.%d", mrand.IntN(4), mrand.IntN(256), 1+mrand.IntN(254))
}
func sid() string {
	return fmt.Sprintf("S-1-5-21-1004336348-1177238915-682003330-%d", 1100+mrand.IntN(2000))
}

func logon4624(host string, rec uint64, t string) (string, string) {
	lt := []int{2, 3, 3, 3, 5, 7, 10, 11}[mrand.IntN(8)]
	data := fmt.Sprintf(`<EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='SubjectUserName'>%s$</Data><Data Name='SubjectDomainName'>LAB</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='TargetUserSid'>%s</Data><Data Name='TargetUserName'>%s</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='TargetLogonId'>%s</Data><Data Name='LogonType'>%d</Data><Data Name='LogonProcessName'>Kerberos</Data><Data Name='AuthenticationPackageName'>Kerberos</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{00000000-0000-0000-0000-000000000000}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>%s</Data><Data Name='IpPort'>%d</Data><Data Name='ImpersonationLevel'>%%%%1833</Data><Data Name='ElevatedToken'>%%%%1843</Data></EventData>`,
		host, sid(), user(), logonID(), lt, ip(), 49152+mrand.IntN(16000))
	return "Security", wrap(secSys(4624, 2, 12544, "0x8020000000000000", t, rec, host), data)
}

func logoff4634(host string, rec uint64, t string) (string, string) {
	data := fmt.Sprintf(`<EventData><Data Name='TargetUserSid'>%s</Data><Data Name='TargetUserName'>%s</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='TargetLogonId'>%s</Data><Data Name='LogonType'>3</Data></EventData>`,
		sid(), user(), logonID())
	return "Security", wrap(secSys(4634, 0, 12545, "0x8020000000000000", t, rec, host), data)
}

func failed4625(host string, rec uint64, t string) (string, string) {
	data := fmt.Sprintf(`<EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>%s</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>WS%03d</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>%s</Data><Data Name='IpPort'>%d</Data></EventData>`,
		user(), mrand.IntN(500), ip(), 49152+mrand.IntN(16000))
	return "Security", wrap(secSys(4625, 0, 12544, "0x8010000000000000", t, rec, host), data)
}

func process4688(host string, rec uint64, t string) (string, string) {
	p := processes[mrand.IntN(len(processes))]
	data := fmt.Sprintf(`<EventData><Data Name='SubjectUserSid'>%s</Data><Data Name='SubjectUserName'>%s</Data><Data Name='SubjectDomainName'>LAB</Data><Data Name='SubjectLogonId'>%s</Data><Data Name='NewProcessId'>0x%x</Data><Data Name='NewProcessName'>%s</Data><Data Name='TokenElevationType'>%%%%1938</Data><Data Name='ProcessId'>0x%x</Data><Data Name='CommandLine'>"%s" --type=renderer --id=%d</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>C:\Windows\explorer.exe</Data><Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData>`,
		sid(), user(), logonID(), 0x1000+mrand.IntN(0xffff), p, 0x1000+mrand.IntN(0xffff), p, mrand.IntN(100000))
	return "Security", wrap(secSys(4688, 2, 13312, "0x8020000000000000", t, rec, host), data)
}

func app1000(host string, rec uint64, t string) (string, string) {
	sys := fmt.Sprintf(sysFmt, "Application Error", "a0e9b465-b939-57d7-b27d-95d8e925ff57", 1000, 0, 2, 100, "0x80000000000000",
		t, rec, 6000+mrand.IntN(9000), 0, "Application", host)
	data := fmt.Sprintf(`<EventData><Data>app%d.exe</Data><Data>10.0.%d.0</Data><Data>%08x</Data><Data>KERNELBASE.dll</Data><Data>10.0.26100.1</Data><Data>c0000005</Data><Data>%08x</Data></EventData>`,
		mrand.IntN(50), mrand.IntN(20), mrand.Uint32(), mrand.Uint32())
	return "Application", wrap(sys, data)
}

func system7036(host string, rec uint64, t string) (string, string) {
	sys := fmt.Sprintf(sysFmt, "Service Control Manager", "555908d1-a6d7-4695-8e1e-26931d2012f4", 7036, 0, 4, 0, "0x8080000000000000",
		t, rec, 1232, 2000+mrand.IntN(9000), "System", host)
	svc := []string{"Windows Update", "Background Intelligent Transfer Service", "WinHTTP Web Proxy Auto-Discovery Service", "Windows Modules Installer"}
	state := []string{"running", "stopped"}
	data := fmt.Sprintf(`<EventData><Data Name='param1'>%s</Data><Data Name='param2'>%s</Data></EventData>`,
		svc[mrand.IntN(len(svc))], state[mrand.IntN(2)])
	return "System", wrap(sys, data)
}

func service7045(host string, rec uint64, t string) (string, string) {
	sys := fmt.Sprintf(sysFmt, "Service Control Manager", "555908d1-a6d7-4695-8e1e-26931d2012f4", 7045, 0, 4, 0, "0x8080000000000000",
		t, rec, 1232, 2000+mrand.IntN(9000), "System", host)
	data := fmt.Sprintf(`<EventData><Data Name='ServiceName'>svc%d</Data><Data Name='ImagePath'>C:\Program Files\Vendor\svc%d.exe</Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data><Data Name='AccountName'>LocalSystem</Data></EventData>`,
		mrand.IntN(30), mrand.IntN(30))
	return "System", wrap(sys, data)
}
