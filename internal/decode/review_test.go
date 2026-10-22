// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"testing"

	"siem/internal/contract"
)

// Poprawki z przeglądu etapu 6.
func TestReviewFixes(t *testing.T) {
	// Nagłówek RFC 3164 bez nazwy hosta – znacznik nie jest brany za host.
	h := ParseHeader("<38>Oct  9 13:00:00 sshd[812]: Failed password for root", warsaw, ingested)
	if h.Host != "" || h.App != "sshd" || h.PID != "812" || h.Message != "Failed password for root" {
		t.Fatalf("nagłówek bez hosta: %+v", h)
	}
	if h := ParseHeader("<38>Oct  9 13:00:00 cron: job done", warsaw, ingested); h.Host != "" || h.App != "cron" {
		t.Fatalf("nagłówek bez hosta (bez PID): %+v", h)
	}

	// Zbiory zarezerwowane i wielkie litery.
	for _, ds := range []string{"windows.security", "syslog.generic", "Fortinet.FortiGate", "a b"} {
		y := "id: x1\ntitle: t\ndataset: " + ds + "\nmatch:\n  app: [x]\nparser:\n  type: kv\n"
		if _, err := Parse([]byte(y), warsaw); err == nil {
			t.Errorf("dataset %q powinien zostać odrzucony", ds)
		}
	}

	// Treść wiadomości ani mapowanie nie nadpisują pól systemowych.
	d, err := Parse([]byte("id: app-kv\ntitle: App\ndataset: app.kv\nmatch:\n  app: [myapp]\nparser:\n  type: kv\n"+
		"fields:\n  syslog.peer: user\n"), warsaw)
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet([]*Decoder{d})
	e, err := Event(contract.Event{ID: "x", Raw: "<14>Oct  9 13:00:00 h myapp: user=10.6.6.6 decoder.id=fortigate siem.reprocess_job=7 ok=1",
		Peer: "192.168.88.1"}, "c", ingested, set, warsaw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Fields["syslog.peer"] != "192.168.88.1" || e.Fields["decoder.id"] != "app-kv" || e.Fields["siem.reprocess_job"] != "" || e.Fields["ok"] != "1" {
		t.Fatalf("pola systemowe: %v", e.Fields)
	}
}
