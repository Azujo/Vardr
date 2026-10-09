package contract

import (
	"regexp"
	"testing"
	"time"
)

func TestEventID(t *testing.T) {
	got := EventID("agt-1", "Security", 2, 1849302)
	if want := "agt-1:Security:g2:1849302"; got != want {
		t.Fatalf("EventID = %q, want %q", got, want)
	}
}

func TestNewBatchIDIsUUIDv7(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	a, b := NewBatchID(), NewBatchID()
	if !re.MatchString(a) {
		t.Fatalf("niepoprawny UUIDv7: %s", a)
	}
	if a == b {
		t.Fatal("dwa kolejne identyfikatory są identyczne")
	}
}

func TestValidate(t *testing.T) {
	valid := func() Batch {
		return Batch{
			Schema: SchemaBatchV1, BatchID: NewBatchID(), AgentID: "agt-1", SentAt: time.Now(),
			Events: []Event{{ID: "agt-1:System:g0:1", Source: "wineventlog:System", Raw: "<Event/>"}},
		}
	}
	b := valid()
	if err := b.Validate(); err != nil {
		t.Fatalf("poprawna paczka odrzucona: %v", err)
	}
	b.Events[0].Peer = "fd00::1"
	if err := b.Validate(); err != nil {
		t.Fatalf("peer IPv6 odrzucony: %v", err)
	}

	cases := map[string]func(*Batch){
		"zły schemat":     func(b *Batch) { b.Schema = "x" },
		"brak batch_id":   func(b *Batch) { b.BatchID = "" },
		"brak zdarzeń":    func(b *Batch) { b.Events = nil },
		"obcy prefiks id": func(b *Batch) { b.Events[0].ID = "agt-2:System:g0:1" },
		"puste raw":       func(b *Batch) { b.Events[0].Raw = "" },
		"brak source":     func(b *Batch) { b.Events[0].Source = "" },
		"za dużo zdarzeń": func(b *Batch) { b.Events = make([]Event, MaxEventsPerBatch+1) },
		"peer nie IP":     func(b *Batch) { b.Events[0].Peer = "fw01; DROP" },
	}
	for name, mutate := range cases {
		b := valid()
		mutate(&b)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: oczekiwano błędu", name)
		}
	}
}
