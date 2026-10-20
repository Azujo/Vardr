package detector

import (
	"testing"
	"time"

	"siem/internal/alerts"
	"siem/internal/detect"
	"siem/internal/model"
)

// Reguła próbna liczy trafienia godzinami i komputerami, bez alertów;
// liczniki po nieudanym zapisie wracają do następnego.
func TestTrialCounting(t *testing.T) {
	r, err := detect.Parse([]byte(`title: Próba
id: trial-1
level: high
logsource: {product: windows, service: security}
detection: {sel: {EventID: 4625}, condition: sel}
vardr: {enabled: false}
`), "sigmahq/x.yml")
	if err != nil {
		t.Fatal(err)
	}
	ov := map[string]alerts.Override{"trial-1": {Trial: true}}
	ApplyOverrides([]*detect.Rule{r}, ov)
	e := NewEngine()
	e.SetRules([]*detect.Rule{r})
	e.SetTrial(TrialRules([]*detect.Rule{r}, ov))
	t0 := time.Date(2026, 10, 20, 10, 5, 0, 0, time.UTC)
	ev := func(id, host string, at time.Time, code uint32) model.Event {
		return model.Event{ID: id, Timestamp: at, HostName: host, Code: code, Dataset: "windows.security",
			Fields: map[string]string{"winlog.channel": "Security"}}
	}
	b := &model.Batch{Events: []model.Event{
		ev("e1", "pc1", t0, 4625), ev("e2", "pc1", t0.Add(time.Minute), 4625), ev("e3", "pc2", t0, 4625),
		ev("e4", "pc1", t0.Add(time.Hour), 4625), ev("e5", "pc1", t0, 4624),
	}}
	if hits, _ := e.Evaluate(b); len(hits) != 0 {
		t.Fatalf("reguła próbna nie tworzy alertów: %+v", hits)
	}
	got := e.TakeTrial()
	byKey := map[string]alerts.TrialHit{}
	for _, h := range got {
		byKey[h.Host+"@"+h.Hour.Format("15")] = h
	}
	if len(got) != 3 || byKey["pc1@10"].Hits != 2 || byKey["pc1@10"].SampleEventID != "e2" || byKey["pc2@10"].Hits != 1 ||
		byKey["pc1@11"].Hits != 1 || byKey["pc1@10"].SampleSummary == "" {
		t.Fatalf("liczniki prób: %+v", got)
	}
	if again := e.TakeTrial(); len(again) != 0 {
		t.Fatalf("po odczycie liczniki od zera: %+v", again)
	}
	e.GiveBackTrial(got)
	e.Evaluate(&model.Batch{Events: []model.Event{ev("e6", "pc1", t0.Add(2*time.Minute), 4625)}})
	for _, h := range e.TakeTrial() {
		if h.Host == "pc1" && h.Hour.Equal(t0.Truncate(time.Hour)) && (h.Hits != 3 || h.SampleEventID != "e6") {
			t.Fatalf("po zwrocie: %+v", h)
		}
	}
	// Wyjście z próby: reguła nie liczy.
	e.SetTrial(TrialRules([]*detect.Rule{r}, nil))
	e.Evaluate(b)
	if got := e.TakeTrial(); len(got) != 0 {
		t.Fatalf("poza próbą: %+v", got)
	}
}
