package detector

import (
	"strings"
	"testing"
	"time"

	"siem/server/internal/detect"
	"siem/server/internal/model"
)

func TestEngineHits(t *testing.T) {
	rules, errs, err := detect.LoadDir("../../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	e := NewEngine()
	if n := e.SetRules(rules); n != len(rules) {
		t.Fatalf("reguły w locie: %d", n)
	}
	ts := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	b := &model.Batch{Events: []model.Event{
		{ID: "a:Security:g0:1", AgentID: "a", Code: 4732, HostName: "dc01", UserName: "admin", UserDomain: "LAB", Timestamp: ts,
			Fields: map[string]string{"winlog.channel": "Security", "TargetSid": "S-1-5-32-551", "TargetUserName": "Backup Operators",
				"MemberName": "CN=test,DC=lab"}},
		{ID: "a:Security:g0:2", AgentID: "a", Code: 4688, HostName: "pc1", Timestamp: ts,
			Fields: map[string]string{"winlog.channel": "Security", "NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": "powershell -enc AAAA", "TargetUserName": "-"}},
		{ID: "a:Security:g0:3", AgentID: "a", Code: 4624, Timestamp: ts, Fields: map[string]string{"winlog.channel": "Security"}},
	}}
	hits, _ := e.Evaluate(b)
	if len(hits) != 2 {
		t.Fatalf("trafienia: %+v", hits)
	}
	g, ps := hits[0], hits[1]
	if g.GroupKey != g.EventID || g.GroupFields != nil || !strings.Contains(g.Summary, "członek: CN=test") || !strings.Contains(g.Summary, `LAB\admin`) {
		t.Fatalf("grupa: %+v", g)
	}
	if ps.GroupFields["Computer"] != "pc1" || ps.Suppress != time.Hour || strings.Contains(ps.Summary, "cel: -") ||
		!strings.Contains(ps.Summary, "polecenie: powershell -enc") {
		t.Fatalf("PowerShell: %+v", ps)
	}
}
