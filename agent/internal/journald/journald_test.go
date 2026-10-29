// SPDX-License-Identifier: AGPL-3.0-or-later

package journald

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
	"siem/internal/contract"
	"siem/internal/decode"
)

const sshd = `{"__CURSOR":"s=abc;i=1f2;b=7;m=9;t=6230;x=1","__REALTIME_TIMESTAMP":"1761645600123456","PRIORITY":"6","SYSLOG_FACILITY":"10",` +
	`"SYSLOG_IDENTIFIER":"sshd","_PID":"4242","_HOSTNAME":"web01","_SYSTEMD_UNIT":"ssh.service",` +
	`"MESSAGE":"Failed password for root from 203.0.113.20 port 41000 ssh2"}`

func TestRecord(t *testing.T) {
	s := &Source{Host: "fallback"}
	rec, ok := s.Record([]byte(sshd), 0)
	if !ok {
		t.Fatal("wpis odrzucony")
	}
	want := "<86>1 2025-10-28T10:00:00.123456Z web01 sshd 4242 - - Failed password for root from 203.0.113.20 port 41000 ssh2"
	if rec.Raw != want || rec.RecordID != 1761645600123456 || rec.Source != SourceName || rec.Channel != Channel || len(rec.Key) != 24 {
		t.Fatalf("%+v", rec)
	}
	// Serwer rozbiera linię jak syslog: program, host, czas i wiadomość.
	h := decode.ParseHeader(rec.Raw, time.UTC, time.Now())
	if h.Format != "rfc5424" || h.App != "sshd" || h.Host != "web01" || h.PID != "4242" || h.Facility != 10 || h.Severity != 6 ||
		!h.Time.Equal(rec.CreatedAt) || !strings.HasPrefix(h.Message, "Failed password") {
		t.Fatalf("%+v", h)
	}

	// Numer niemalejący: wpis o tej samej albo wcześniejszej chwili dostaje kolejny numer.
	again, _ := s.Record([]byte(sshd), rec.RecordID)
	if again.RecordID != rec.RecordID+1 || again.Key != rec.Key {
		t.Fatalf("%d %s", again.RecordID, again.Key)
	}

	// Wiadomość w bajtach (niepoprawne UTF-8), brak hosta i programu, jądro.
	kern := `{"__REALTIME_TIMESTAMP":"1761645600000000","_TRANSPORT":"kernel","PRIORITY":"4","_COMM":"kworker","MESSAGE":[111,107,32,255]}`
	k, ok := s.Record([]byte(kern), 0)
	if !ok || k.Raw != "<4>1 2025-10-28T10:00:00.000000Z fallback kworker - - - ok �" || k.Key != "" {
		t.Fatalf("%q", k.Raw)
	}

	// Własne wpisy agenta i wpisy bez czasu są pomijane.
	for _, l := range []string{`{"__REALTIME_TIMESTAMP":"1","_SYSTEMD_UNIT":"vardr-agent.service","MESSAGE":"x"}`, `{"MESSAGE":"x"}`, `nie json`} {
		if _, ok := s.Record([]byte(l), 0); ok {
			t.Fatalf("przyjęty: %s", l)
		}
	}
}

func TestArgs(t *testing.T) {
	s := &Source{Filter: Filter{Units: []string{"nginx.service"}, Identifiers: []string{"cron"}}}
	a := s.Args(source.Position{RecordID: 1761645600123456, Valid: true})
	if !slices.Contains(a, "--since=@1761645600.123456") || slices.Contains(a, "--lines=0") {
		t.Fatal(a)
	}
	m := strings.Join(s.Filter.Matches(), " ")
	if m != "SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + PRIORITY=0 PRIORITY=1 PRIORITY=2 PRIORITY=3 PRIORITY=4 + _SYSTEMD_UNIT=nginx.service + SYSLOG_IDENTIFIER=cron" {
		t.Fatal(m)
	}
	if a := s.Args(source.Position{}); !slices.Contains(a, "--lines=0") {
		t.Fatal(a)
	}
	if a := s.Args(source.Position{Oldest: true}); slices.Contains(a, "--lines=0") || strings.Contains(strings.Join(a, " "), "--since") {
		t.Fatal(a)
	}
	if (Filter{All: true}).Matches() != nil {
		t.Fatal("All: bez dopasowań")
	}
}

// Wznowienie: wpisy do zapisanej chwili włącznie są pomijane.
func TestReadSkipsSent(t *testing.T) {
	entry := func(us string) string {
		return `{"__CURSOR":"c` + us + `","__REALTIME_TIMESTAMP":"` + us + `","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"m"}` + "\n"
	}
	in := entry("100") + entry("200") + "\n" + entry("300")
	s := &Source{}
	pos := source.Position{RecordID: 200, Valid: true}
	out := make(chan source.Record, 10)
	if err := s.read(context.Background(), strings.NewReader(in), &pos, out); err != nil {
		t.Fatal(err)
	}
	close(out)
	var got []uint64
	for r := range out {
		got = append(got, r.RecordID)
	}
	if !slices.Equal(got, []uint64{300}) || pos.RecordID != 300 {
		t.Fatal(got, pos)
	}
}

// Serwer: wpis z journald przechodzi przez wbudowany dekoder Linuksa.
func TestServerDecodes(t *testing.T) {
	ds, err := decode.Builtin(time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := (&Source{}).Record([]byte(sshd), 0)
	e, err := decode.Event(contract.Event{ID: "a:journald:k:" + rec.Key, Source: rec.Source, Raw: rec.Raw}, "a",
		rec.CreatedAt.Add(time.Second), decode.NewSet(ds), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "linux.auth" || e.HostName != "web01" || e.SourceIP != "203.0.113.20" || e.UserName != "root" ||
		e.Outcome != "failure" || !e.Timestamp.Equal(rec.CreatedAt) {
		t.Fatalf("%+v", e)
	}
}
