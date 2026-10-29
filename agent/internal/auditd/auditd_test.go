// SPDX-License-Identifier: AGPL-3.0-or-later

package auditd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
)

const sample = `type=SYSCALL msg=audit(1793268000.123:100): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 comm="curl" exe="/usr/bin/curl" key="vardr_exec"
type=EXECVE msg=audit(1793268000.123:100): argc=2 a0="curl" a1="http://203.0.113.5/"
type=PROCTITLE msg=audit(1793268000.123:100): proctitle=6375726C
type=EOE msg=audit(1793268000.123:100):
type=CRED_ACQ msg=audit(1793268001.000:101): pid=1 uid=0 auid=0 ses=1 msg='op=PAM:setcred acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
type=USER_LOGIN msg=audit(1793268002.000:102): pid=2 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=203.0.113.9 terminal=ssh res=failed'
type=SYSCALL msg=audit(1793268003.000:103): arch=c000003e syscall=257 success=yes exit=3 auid=0 uid=0 comm="vardr-agent" exe="/usr/local/sbin/vardr-agent" key="x"
type=EOE msg=audit(1793268003.000:103):
type=SYSCALL msg=audit(1793268004.000:104): arch=c000003e syscall=257 success=yes exit=3 auid=1000 uid=0 comm="vi" exe="/usr/bin/vi" key="vardr_identity"
type=PATH msg=audit(1793268004.000:104): item=0 name="/etc/shadow" nametype=NORMAL
`

func collect(t *testing.T, s *Source, start source.Position, want int) ([]source.Record, context.CancelFunc, chan source.Position) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan source.Record, 100)
	done := make(chan source.Position, 1)
	go func() {
		pos, _ := s.Run(ctx, start, out)
		done <- pos
	}()
	var recs []source.Record
	deadline := time.After(5 * time.Second)
	for len(recs) < want {
		select {
		case r := <-out:
			recs = append(recs, r)
		case <-deadline:
			cancel()
			t.Fatalf("got %d of %d records: %+v", len(recs), want, recs)
		}
	}
	return recs, cancel, done
}

func TestGroupsAndFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	ex := map[string]bool{}
	for _, t := range DefaultExclude {
		ex[t] = true
	}
	s := &Source{Path: path, Exclude: ex, Oldest: true, Host: "web01", SelfExe: "/usr/local/sbin/vardr-agent", Poll: 20 * time.Millisecond}
	recs, cancel, done := collect(t, s, source.Position{}, 3)
	defer cancel()
	// 1: execve (4 wiersze), 2: USER_LOGIN (CRED_ACQ pominięty), 3: PATH bez EOE – po chwili ciszy.
	if n := strings.Count(recs[0].Raw, "\n"); n != 3 || !strings.HasPrefix(recs[0].Raw, "node=web01 type=SYSCALL") || recs[0].Source != SourceName {
		t.Fatalf("execve: %q", recs[0].Raw)
	}
	if !strings.Contains(recs[1].Raw, "USER_LOGIN") || strings.Contains(recs[1].Raw, "\n") {
		t.Fatalf("login: %q", recs[1].Raw)
	}
	if !strings.Contains(recs[2].Raw, "/etc/shadow") || strings.Count(recs[2].Raw, "\n") != 1 {
		t.Fatalf("watch: %q", recs[2].Raw)
	}
	if !(recs[0].RecordID < recs[1].RecordID && recs[1].RecordID < recs[2].RecordID) || recs[0].Key == recs[1].Key {
		t.Fatalf("numbering: %d %d %d", recs[0].RecordID, recs[1].RecordID, recs[2].RecordID)
	}
	if got := recs[0].CreatedAt.Format(time.RFC3339Nano); got != "2026-10-29T10:00:00.123Z" {
		t.Fatalf("time %s", got)
	}

	cancel()
	pos := <-done
	if !pos.Valid {
		t.Fatal("no position")
	}

	// Wznowienie od pozycji: tylko późniejsze zdarzenia.
	again, cancel2, _ := collect(t, s, source.Position{RecordID: recs[1].RecordID, Valid: true}, 1)
	defer cancel2()
	if !strings.Contains(again[0].Raw, "/etc/shadow") {
		t.Fatalf("resume: %q", again[0].Raw)
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	for _, n := range []string{"audit.log", "audit.log.1", "audit.log.2", "audit.log.10", "audit.log.bak"} {
		_ = os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	got := Files(p)
	var names []string
	for _, f := range got {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, ",") != "audit.log.10,audit.log.2,audit.log.1,audit.log" {
		t.Fatalf("files: %v", names)
	}
}
