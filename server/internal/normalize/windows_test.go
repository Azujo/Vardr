package normalize

import (
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
)

var ingested = time.Date(2026, 10, 6, 20, 0, 0, 0, time.UTC)

func ev(source, raw string) contract.Event {
	return contract.Event{ID: "agt-1:x:g0:1", Source: source, Raw: raw}
}

// Prawdziwe zdarzenie z komputera laboratoryjnego (System 7045).
const sys7045 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-10-06T19:53:35.6621098Z'/><EventRecordID>20451</EventRecordID><Correlation/><Execution ProcessID='1232' ThreadID='15856'/><Channel>System</Channel><Computer>DESKTOP-DU4PUFV</Computer><Security UserID='S-1-5-21-807202919-2637959309-2781131931-1001'/></System><EventData><Data Name='ServiceName'>WinFsp</Data><Data Name='ImagePath'>C:\WINDOWS\system32\drivers\BvWinFsp.sys</Data><Data Name='ServiceType'>sterownik trybu jądra</Data><Data Name='StartType'>uruchamianie na żądanie</Data><Data Name='AccountName'></Data></EventData></Event>`

// Prawdziwe zdarzenie z dziennika Application (nienazwane pole Data).
const app999 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error' Guid='{a0e9b465-b939-57d7-b27d-95d8e925ff57}' EventSourceName='Application Error'/><EventID Qualifiers='0'>999</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-06T11:16:20.9860775Z'/><EventRecordID>19734</EventRecordID><Correlation/><Execution ProcessID='15268' ThreadID='0'/><Channel>Application</Channel><Computer>DESKTOP-DU4PUFV</Computer><Security/></System><EventData><Data>SIEM test live 1</Data></EventData></Event>`

// Format zdarzenia 4625 wg dokumentacji Microsoft (wartości przykładowe).
const sec4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-10-06T19:58:01.123Z'/><EventRecordID>88213</EventRecordID><Correlation/><Execution ProcessID='812' ThreadID='4120'/><Channel>Security</Channel><Computer>DC01.lab.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>jkowalski</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>KALI</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>::ffff:10.0.5.23</Data><Data Name='IpPort'>51234</Data></EventData></Event>`

const sec1102 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/><EventID>1102</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2026-10-06T19:59:00Z'/><EventRecordID>1</EventRecordID><Correlation/><Execution ProcessID='1200' ThreadID='1300'/><Channel>Security</Channel><Computer>DC01.lab.local</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName><SubjectLogonId>0x3e7</SubjectLogonId></LogFileCleared></UserData></Event>`

const sysmon1 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-06T19:59:30.5Z'/><EventRecordID>5</EventRecordID><Correlation/><Execution ProcessID='3000' ThreadID='3100'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>PC01.lab.local</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>powershell -enc SQBFAFgA</Data><Data Name='User'>LAB\jkowalski</Data><Data Name='ParentImage'>C:\Windows\explorer.exe</Data></EventData></Event>`

func TestSystem7045RealEvent(t *testing.T) {
	e, err := Event(ev("wineventlog:System", sys7045), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "windows.system" || e.Code != 7045 || e.Action != "service-installed" ||
		e.HostName != "desktop-du4pufv" || e.ProcessName != `C:\WINDOWS\system32\drivers\BvWinFsp.sys` ||
		e.Fields["ServiceName"] != "WinFsp" || e.Fields["winlog.record_id"] != "20451" || e.Parser != "winevt-1" {
		t.Fatalf("%+v", e)
	}
	if want := time.Date(2026, 10, 6, 19, 53, 35, 662109800, time.UTC); !e.Timestamp.Equal(want) || e.TimeQuality != "" {
		t.Fatalf("czas: %v (%q)", e.Timestamp, e.TimeQuality)
	}
}

func TestApplicationUnnamedDataBecomesMessage(t *testing.T) {
	e, err := Event(ev("wineventlog:Application", app999), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Message != "SIEM test live 1" || e.Fields["param1"] != "SIEM test live 1" || e.Dataset != "windows.application" {
		t.Fatalf("%+v", e)
	}
}

func TestSecurity4625FailedLogon(t *testing.T) {
	e, err := Event(ev("wineventlog:Security", sec4625), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Action != "logon-failed" || e.Outcome != "failure" || e.UserName != "jkowalski" || e.UserDomain != "LAB" ||
		e.SourceIP != "10.0.5.23" || e.ProcessName != "" || e.Fields["LogonType"] != "3" || e.HostName != "dc01.lab.local" {
		t.Fatalf("%+v", e)
	}
}

func TestSecurity1102UserData(t *testing.T) {
	e, err := Event(ev("wineventlog:Security", sec1102), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Action != "audit-log-cleared" || e.UserName != "Administrator" || e.UserDomain != "LAB" ||
		e.Outcome != "success" {
		t.Fatalf("%+v", e)
	}
	if _, parentAsField := e.Fields["LogFileCleared"]; parentAsField {
		t.Fatal("element nadrzędny UserData nie powinien być polem")
	}
}

func TestSysmonProcessCreate(t *testing.T) {
	e, err := Event(ev("wineventlog:Microsoft-Windows-Sysmon/Operational", sysmon1), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "windows.sysmon" || e.Action != "process-created" || e.UserName != "jkowalski" || e.UserDomain != "LAB" ||
		!strings.HasSuffix(e.ProcessName, `powershell.exe`) || e.CommandLine != "powershell -enc SQBFAFgA" {
		t.Fatalf("%+v", e)
	}
}

func TestTimeQuality(t *testing.T) {
	future := strings.Replace(app999, "2026-10-06T11:16:20.9860775Z", "2026-10-07T20:00:00Z", 1)
	if e, _ := Event(ev("wineventlog:Application", future), "a", ingested); e.TimeQuality != "future" {
		t.Errorf("czas z przyszłości: %q", e.TimeQuality)
	}
	missing := strings.Replace(app999, "<TimeCreated SystemTime='2026-10-06T11:16:20.9860775Z'/>", "", 1)
	if e, _ := Event(ev("wineventlog:Application", missing), "a", ingested); e.TimeQuality != "missing" || !e.Timestamp.Equal(ingested) {
		t.Errorf("brak czasu: %q %v", e.TimeQuality, e.Timestamp)
	}
	for _, bad := range []string{"1601-01-01T00:00:00Z", "2999-01-01T00:00:00Z"} {
		x := strings.Replace(app999, "2026-10-06T11:16:20.9860775Z", bad, 1)
		if e, _ := Event(ev("wineventlog:Application", x), "a", ingested); e.TimeQuality != "invalid" || !e.Timestamp.Equal(ingested) {
			t.Errorf("czas %s: %q %v", bad, e.TimeQuality, e.Timestamp)
		}
	}
}

func TestBatchQuarantinesBadEventsWithoutStoppingOthers(t *testing.T) {
	b := contract.Batch{BatchID: "b1", Events: []contract.Event{
		ev("wineventlog:System", sys7045),
		ev("wineventlog:System", "<Event><System>uszkodzone"),
		ev("netflow:v9", "binarne dane netflow"),
		{ID: "agt-1:x:g0:9", Source: "wineventlog:Application", Raw: app999[:200], Truncated: true},
		ev("wineventlog:Application", app999),
	}}
	nb := Batch(b, "agt-1", ingested)
	if len(nb.Events) != 2 || len(nb.Quarantine) != 3 {
		t.Fatalf("zdarzenia %d, kwarantanna %d", len(nb.Events), len(nb.Quarantine))
	}
	reasons := nb.Quarantine[0].Reason + nb.Quarantine[1].Reason + nb.Quarantine[2].Reason
	for _, want := range []string{"niepoprawny XML", "brak dekodera", "przycięte"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("brak powodu %q w %q", want, reasons)
		}
	}
	if nb.Quarantine[1].Raw != "binarne dane netflow" {
		t.Error("kwarantanna musi zachować oryginał")
	}
}

func TestDataset(t *testing.T) {
	if d := Dataset("Microsoft-Windows-TaskScheduler/Operational"); d != "windows.microsoft_windows_taskscheduler_operational" {
		t.Fatal(d)
	}
}

// Syslog z kolektora trafia do dekoderów (FortiGate) zamiast do kwarantanny.
func TestBatchDecodesSyslog(t *testing.T) {
	raw := `<189>date=2026-10-09 time=13:05:12 devname="FGT-HQ" tz="+0200" logid="0101039426" type="event" subtype="vpn" action="ssl-login-fail" remip=203.0.113.45 user="jkowalski"`
	nb := Batch(contract.Batch{BatchID: "b2", Events: []contract.Event{{ID: "agt-c:syslog:g0:1", Source: "syslog:udp", Raw: raw, Peer: "10.0.0.1"}}},
		"agt-c", ingested)
	if len(nb.Events) != 1 || nb.Events[0].Dataset != "fortinet.fortigate" || nb.Events[0].UserName != "jkowalski" || nb.Events[0].Outcome != "failure" {
		t.Fatalf("syslog FortiGate: %+v kwarantanna %+v", nb.Events, nb.Quarantine)
	}
}
