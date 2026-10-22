// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/internal/contract"
	"siem/internal/urd"
)

const xml4625 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-10-07T10:%02d:00.000Z'/><Channel>Security</Channel><Computer>DC01.lab.local</Computer></System><EventData><Data Name='TargetUserName'>jkowalski</Data><Data Name='TargetDomainName'>LAB</Data><Data Name='IpAddress'>10.0.5.23</Data><Data Name='LogonType'>3</Data></EventData></Event>`

func batch(t *testing.T, id string, minute int) []byte {
	t.Helper()
	return pack(contract.Batch{Schema: "vardr.batch/1", BatchID: id, AgentID: "agt-dc01", Events: []contract.Event{
		{ID: "agt-dc01:Security:g1:" + id, Source: "Security", Raw: fmt.Sprintf(xml4625, minute)},
	}})
}

// syslogRaw: wiadomość z routera przez kolektor (zdarzenie bez XML).
const syslogRaw = "<131>Oct  7 12:00:30 MikroTik login failure for user admin from 203.0.113.9 via ssh"

func pack(b contract.Batch) []byte {
	data, _ := json.Marshal(b)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

// enrich udaje normalizator serwera (pola ECS).
func enrich(ev contract.Event, _ string, _ time.Time, r *urd.Readable) {
	if strings.HasPrefix(ev.Source, "syslog:") {
		r.Dataset, r.Action, r.Outcome, r.UserName, r.SourceIP, r.HostName = "mikrotik.routeros", "login", "failure", "admin", "203.0.113.9", "mikrotik"
		r.Timestamp = time.Date(2026, 10, 7, 10, 0, 30, 0, time.UTC).Format(time.RFC3339Nano)
		return
	}
	r.Code, r.HostName, r.UserName, r.UserDomain, r.SourceIP, r.Outcome = 4625, "dc01.lab.local", "jkowalski", "LAB", "10.0.5.23", "failure"
	r.Timestamp = time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
}

// buildPackage tworzy prawdziwą paczkę eksportu (.tar) przez publiczne API urd.
func buildPackage(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 10, 5, 0, 0, time.UTC)
	a := urd.New(t.TempDir(), urd.NewMemCatalog())
	a.Now = func() time.Time { return now }
	w, err := a.OpenSegment()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_ = w.Add(urd.RecordMeta{Agent: "agt-dc01", Batch: fmt.Sprintf("b%d", i), ReceivedAt: now}, batch(t, fmt.Sprintf("b%d", i), i))
	}
	_ = w.Add(urd.RecordMeta{Agent: "agt-col", Batch: "s1", ReceivedAt: now}, pack(contract.Batch{Schema: "vardr.batch/1",
		BatchID: "s1", AgentID: "agt-col", Events: []contract.Event{{ID: "agt-col:syslog:g0:1", Source: "syslog:udp", Peer: "192.168.88.1", Raw: syslogRaw}}}))
	if _, err := w.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err := a.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	p, err := a.PlanExport(ctx, from, from.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "urd-eksport-9-2026100710-2026100711.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.WriteExport(ctx, urd.ExportJob{ID: 9, RequestedBy: "adam", Reason: "incydent INC-1", From: from, To: from.Add(time.Hour)},
		p, f, urd.ExportOptions{Version: "test", TempDir: t.TempDir(), Enrich: enrich}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return path
}

func TestReaderProducesReport(t *testing.T) {
	pkg := buildPackage(t)
	dir, err := extract(pkg)
	if err != nil {
		t.Fatal(err)
	}
	report, ok, err := Run(dir, time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC))
	if err != nil || !ok {
		t.Fatalf("odczyt: %v ok=%v", err, ok)
	}
	rep, _ := os.ReadFile(report)
	for _, want := range []string{"ZGODNE", "incydent INC-1", "Nieudane logowanie", "3 × LAB\\jkowalski", "10.0.5.23",
		"ODCZYT\\zdarzenia\\2026-10-07.txt   – 4 zdarzeń", "1 × admin  (mikrotik)", "1 × 203.0.113.9", "1 × syslog  mikrotik.routeros  login"} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("raport bez %q:\n%s", want, rep)
		}
	}
	day, err := os.ReadFile(filepath.Join(dir, "ODCZYT", "zdarzenia", "2026-10-07.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"12:00:00 (czas polski)", "4625  Nieudane logowanie  [porażka]", "TargetUserName", "= jkowalski", "= 3 (sieciowe – np. udział, zasób)",
		"LogonType", "\r\n", "syslog  mikrotik.routeros  login  [porażka]", "Nadawca:        192.168.88.1   (syslog:udp, zbiór danych: mikrotik.routeros)",
		"Treść:          " + syslogRaw} {
		if !strings.Contains(string(day), want) {
			t.Errorf("plik dzienny bez %q", want)
		}
	}

	// Ponowny odczyt (folder ODCZYT już istnieje) nie psuje wyniku sprawdzenia.
	if _, ok, err := Run(dir, time.Now()); err != nil || !ok {
		t.Fatalf("ponowny odczyt: %v ok=%v", err, ok)
	}

	// Zmiana pliku paczki: raport ostrzega o niezgodnościach.
	csvPath := filepath.Join(dir, "zdarzenia", "zdarzenia.csv")
	_ = os.Chmod(csvPath, 0o644)
	if err := os.WriteFile(csvPath, []byte("zmienione"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, ok, err = Run(dir, time.Now())
	if err != nil || ok {
		t.Fatalf("zmieniona paczka powinna dać niezgodności: %v ok=%v", err, ok)
	}
	if rep, _ := os.ReadFile(report); !strings.Contains(string(rep), "NIEZGODNOŚCI") {
		t.Fatal("raport bez ostrzeżenia o niezgodnościach")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	if _, _, err := runFor(filepath.Join(t.TempDir(), "brak.tar")); err == nil {
		t.Fatal("brakujący plik powinien dać błąd")
	}
}

func TestReaderSplitsLargeDays(t *testing.T) {
	old := maxPerFile
	maxPerFile = 2
	defer func() { maxPerFile = old }()
	dir, err := extract(buildPackage(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Run(dir, time.Now()); err != nil || !ok {
		t.Fatalf("odczyt: %v %v", err, ok)
	}
	for _, f := range []string{"2026-10-07.txt", "2026-10-07_czesc2.txt"} {
		if _, err := os.Stat(filepath.Join(dir, "ODCZYT", "zdarzenia", f)); err != nil {
			t.Errorf("brak pliku %s: %v", f, err)
		}
	}
}
