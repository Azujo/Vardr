// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package auditd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"siem/agent/internal/source"
)

// Śledzenie pliku z rotacją auditd (audit.log → audit.log.1, nowy audit.log).
func TestFollowRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	line := func(serial int, user string) string {
		return "type=USER_LOGIN msg=audit(1793268000.000:" + strconv.Itoa(serial) + "): pid=1 uid=0 auid=4294967295 msg='op=login acct=\"" +
			user + "\" exe=\"/usr/sbin/sshd\" addr=203.0.113.9 res=failed'\n"
	}
	if err := os.WriteFile(path, []byte(line(1, "old")), 0o600); err != nil {
		t.Fatal(err)
	}
	appendLine := func(p, l string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = f.WriteString(l)
		f.Close()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		appendLine(path, line(2, "a"))
		time.Sleep(100 * time.Millisecond)
		l3 := line(3, "b")
		appendLine(path, l3[:40]) // niepełny wiersz przed rotacją
		if err := os.Rename(path, path+".1"); err != nil {
			t.Error(err)
		}
		appendLine(path+".1", l3[40:])
		appendLine(path, line(4, "c"))
	}()
	// Nowy agent: tylko nowe wpisy (bez „old”).
	s := &Source{Path: path, Poll: 20 * time.Millisecond}
	recs, cancel, _ := collect(t, s, source.Position{}, 3)
	cancel()
	var users []string
	for _, r := range recs {
		i := strings.Index(r.Raw, `acct="`)
		users = append(users, r.Raw[i+6:i+7])
	}
	if strings.Join(users, "") != "abc" {
		t.Fatalf("users %v", users)
	}
}
