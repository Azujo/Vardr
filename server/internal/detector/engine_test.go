package detector

import (
	"slices"
	"strings"
	"testing"
	"time"

	"siem/internal/alerts"
	"siem/internal/attack"
	"siem/internal/detect"
	"siem/internal/model"
)

func TestEngineHits(t *testing.T) {
	rules, errs, err := detect.LoadDir("../../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	rules = ownRules(rules)
	e := NewEngine()
	alerting := 0
	for _, r := range rules {
		if r.Alerts() {
			alerting++
		}
	}
	if n := e.SetRules(rules); n != alerting || n == len(rules) {
		t.Fatalf("reguły w locie: %d", n)
	}
	ts := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	b := &model.Batch{Events: []model.Event{
		{ID: "a:Security:g0:1", AgentID: "a", Dataset: "windows.security", Code: 4732, HostName: "dc01", UserName: "admin", UserDomain: "LAB", Timestamp: ts,
			Fields: map[string]string{"winlog.channel": "Security", "TargetSid": "S-1-5-32-551", "TargetUserName": "Backup Operators",
				"MemberName": "CN=test,DC=lab"}},
		{ID: "a:Security:g0:2", AgentID: "a", Dataset: "windows.security", Code: 4688, HostName: "pc1", Timestamp: ts,
			Fields: map[string]string{"winlog.channel": "Security", "NewProcessName": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": "powershell -enc AAAA", "TargetUserName": "-"}},
		{ID: "a:Security:g0:3", AgentID: "a", Dataset: "windows.security", Code: 4624, Timestamp: ts, Fields: map[string]string{"winlog.channel": "Security"}},
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

// Tagi MITRE ATT&CK reguł z repozytorium i wbudowanych: bez nieznanych
// i wycofanych technik (siem-detector check pokazuje je jako UWAGA).
func TestRulesAttackTags(t *testing.T) {
	set, _, err := detect.LoadSet("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	set = ownSet(set)
	d := attack.Enterprise()
	check := func(name string, tags []string, base bool) {
		m := d.Map(tags)
		if len(m.Warnings) > 0 {
			t.Errorf("%s: %v", name, m.Warnings)
		}
		// Reguła bazowa korelacji sama nie alarmuje – technikę ma korelacja;
		// heimdall.attack_dynamic – technika zależy od wykrycia (Defender, ASR).
		if len(m.Techniques) == 0 && !base && !slices.Contains(tags, "heimdall.attack_dynamic") {
			t.Errorf("%s: brak techniki ATT&CK", name)
		}
	}
	for _, r := range set.Rules {
		check(r.File, r.Tags, r.CorrelationOnly)
	}
	for _, c := range set.Correlations {
		check(c.File, c.Tags, false)
	}
	corr, _ := CorrelationInfos(nil)
	for _, r := range append([]alerts.RuleInfo{HeartbeatRule(), TamperRule(), SilenceRule()}, corr...) {
		check(r.ID, r.Tags, false)
	}
}
