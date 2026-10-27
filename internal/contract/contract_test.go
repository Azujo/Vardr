// SPDX-License-Identifier: AGPL-3.0-or-later

package contract

import (
	"regexp"
	"strings"
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

func TestUninstallTokenAndVersion(t *testing.T) {
	tok, err := NewUninstallToken()
	if err != nil || len(tok) != 23 || strings.Count(tok, "-") != 3 || strings.ContainsAny(tok, "01IO") {
		t.Fatalf("%q %v", tok, err)
	}
	if UninstallHash("a", tok) != UninstallHash("a", strings.ToLower(strings.ReplaceAll(tok, "-", " "))) ||
		UninstallHash("a", tok) == UninstallHash("b", tok) {
		t.Fatal("skrót tokenu")
	}
	c := AgentConfig{Profile: "workstation"}
	c.Version = c.ComputeVersion()
	h := UninstallHash("a", tok)
	w := c.WithTokens([]UninstallToken{{ID: UninstallTokenID(h), Hash: h}})
	if w.Version == c.Version || BaseVersion(w.Version) != c.Version || w.Validate() != nil {
		t.Fatalf("%q %q %v", w.Version, c.Version, w.Validate())
	}
	if c.WithTokens(nil).Version != c.Version || w.WithTokens(nil).Version != c.Version {
		t.Fatal("wersja bez tokenów")
	}
	w.UninstallTokens[0].ID = "zly"
	if w.Validate() == nil {
		t.Fatal("niepoprawny identyfikator tokenu przyjęty")
	}
	if !(AgentLimits{}).ProtectionOn() {
		t.Fatal("ochrona domyślnie włączona")
	}
}

func TestAgentUpdate(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		newer bool
	}{
		{"0.10.0", "0.9.0", true}, {"0.9.0", "0.10.0", false}, {"1.0", "0.99.99", true},
		{"0.9.0", "0.9.0", false}, {"0.9.0.1", "0.9.0", true}, {"0.9", "0.9.0", false},
		{"x", "0.1.0", false}, {"0.10.0", "dev", true},
	} {
		if NewerVersion(c.a, c.b) != c.newer {
			t.Errorf("NewerVersion(%q, %q) != %v", c.a, c.b, c.newer)
		}
	}
	if (AgentLimits{}).AutoUpdateOn() {
		t.Fatal("aktualizacje domyślnie wyłączone")
	}
	c := AgentConfig{Profile: "workstation"}
	c.Version = c.ComputeVersion()
	u := &AgentUpdate{Version: "0.10.0", SHA256: strings.Repeat("ab", 32), Size: 1 << 20}
	w := c.WithTokens(nil).WithUpdate(u)
	if w.Version == c.Version || BaseVersion(w.Version) != c.Version || w.Validate() != nil {
		t.Fatalf("%q %q %v", w.Version, c.Version, w.Validate())
	}
	if c.WithUpdate(&AgentUpdate{Version: "0.10.1", SHA256: u.SHA256, Size: 1}).Version == w.Version {
		t.Fatal("nowa wersja agenta nie zmienia wersji konfiguracji")
	}
	for _, bad := range []AgentUpdate{{Version: "1.x", SHA256: u.SHA256, Size: 1}, {Version: "1.0", SHA256: "ab", Size: 1},
		{Version: "1.0", SHA256: u.SHA256, Size: 0}, {Version: "1.0", SHA256: u.SHA256, Size: MaxAgentMSISize + 1}} {
		if (AgentConfig{Profile: "workstation", Update: &bad}).Validate() == nil {
			t.Errorf("przyjęto %+v", bad)
		}
	}
}
