// SPDX-License-Identifier: AGPL-3.0-or-later

package decode

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"

	"siem/internal/lang"
)

// Parser „audit”: zdarzenie Linux Audit (auditd) – jeden albo kilka rekordów
// tego samego zdarzenia, po jednym w wierszu („type=SYSCALL msg=audit(…)”,
// opcjonalnie „node=host ” na początku, w formacie ENRICHED po znaku 0x1d
// pola przetłumaczone: AUID="jan"). Agent Linux grupuje rekordy zdarzenia
// po msg=audit(czas:numer); audisp-syslog przysyła je pojedynczo.
//
// Pola wynikowe: pola rekordów (pierwsze wystąpienie; argumenty EXECVE jako
// a0…aN, tłumaczenia ENRICHED wielkimi literami), a do tego znormalizowane:
//
//	type          EXECVE, jeśli jest (uruchomienie programu), inaczej główny rekord
//	audit.types   typy rekordów w kolejności
//	audit.id      czas:numer zdarzenia, audit.ms – czas w ms od 1970
//	action        login, auth, sudo, process-start, user-created, syscall…
//	outcome       success | failure
//	user          konto logowania (AUID) albo konto docelowe logowania (acct)
//	target_user   konto zmieniane (ADD_USER, USER_MGMT…)
//	cmdline       polecenie (EXECVE albo PROCTITLE)
//	file.path     plik z rekordu PATH (bez katalogów nadrzędnych)
//	src_ip        adres zdalny (addr), dest_ip i dest_port z SOCKADDR
//	message       krótki opis
var auditHeadRe = regexp.MustCompile(`^(?:node=(\S+) )?type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?`)

// auditActions: typ rekordu → event.action.
var auditActions = map[string]string{
	"USER_LOGIN":       "login",
	"USER_LOGOUT":      "logout",
	"USER_AUTH":        "auth",
	"USER_ACCT":        "account-check",
	"USER_CMD":         "sudo",
	"USER_CHAUTHTOK":   "password-change",
	"USER_START":       "session-open",
	"USER_END":         "session-close",
	"USER_ERR":         "auth-error",
	"CRED_ACQ":         "credential-acquire",
	"CRED_DISP":        "credential-dispose",
	"CRED_REFR":        "credential-refresh",
	"ADD_USER":         "user-created",
	"DEL_USER":         "user-deleted",
	"USER_MGMT":        "user-changed",
	"ADD_GROUP":        "group-created",
	"DEL_GROUP":        "group-deleted",
	"GRP_MGMT":         "group-changed",
	"ACCT_LOCK":        "user-locked",
	"ACCT_UNLOCK":      "user-unlocked",
	"CONFIG_CHANGE":    "audit-config-change",
	"DAEMON_CONFIG":    "audit-config-change",
	"DAEMON_START":     "audit-daemon-start",
	"DAEMON_END":       "audit-daemon-stop",
	"DAEMON_ABORT":     "audit-daemon-abort",
	"SYSTEM_BOOT":      "system-boot",
	"SYSTEM_SHUTDOWN":  "system-shutdown",
	"SERVICE_START":    "service-start",
	"SERVICE_STOP":     "service-stop",
	"KERN_MODULE":      "kernel-module",
	"ANOM_ABEND":       "process-crash",
	"ANOM_PROMISCUOUS": "promiscuous-mode",
	"SYSCALL":          "syscall",
}

// auditAux: rekordy pomocnicze zdarzenia wywołania systemowego.
var auditAux = map[string]bool{"SYSCALL": true, "CWD": true, "PATH": true, "PROCTITLE": true, "EOE": true,
	"SOCKADDR": true, "EXECVE": true, "BPRM_FCAPS": true, "OBJ_PID": true, "MMAP": true, "FD_PAIR": true}

// auditHexFields: pola, które auditd zapisuje w hex, gdy wartość ma znaki
// spoza zwykłego ASCII albo spacje (bez cudzysłowu).
var auditHexFields = map[string]bool{"comm": true, "exe": true, "name": true, "proctitle": true, "cwd": true,
	"acct": true, "cmd": true, "path": true, "key": true, "data": true, "new_user": true, "old_user": true}

// targetTypes: rekordy zmian kont – acct to konto zmieniane.
var targetTypes = map[string]bool{"ADD_USER": true, "DEL_USER": true, "USER_MGMT": true, "ADD_GROUP": true,
	"DEL_GROUP": true, "GRP_MGMT": true, "ACCT_LOCK": true, "ACCT_UNLOCK": true, "USER_CHAUTHTOK": true}

type auditRecord struct {
	typ  string
	kv   map[string]string
	ext  map[string]string // ENRICHED (wielkie litery)
	text string
}

// parseAudit rozbiera zdarzenie auditd do out. Błąd – żaden wiersz nie jest
// rekordem auditd.
func parseAudit(msg string, out map[string]string) error {
	var recs []auditRecord
	var node, sec, ms, serial string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		m := auditHeadRe.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		g := func(i int) string {
			if m[2*i] < 0 {
				return ""
			}
			return line[m[2*i]:m[2*i+1]]
		}
		if sec == "" {
			node, sec, ms, serial = g(1), g(3), g(4), g(5)
		}
		body, enriched, _ := strings.Cut(line[m[1]:], "\x1d")
		r := auditRecord{typ: g(2), kv: map[string]string{}, ext: map[string]string{}, text: body}
		auditKV(body, r.kv)
		if enriched != "" {
			auditKV(enriched, r.ext)
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return lang.Errorf("brak rekordu auditd (type=… msg=audit(…))", "no auditd record (type=… msg=audit(…))")
	}

	var types []string
	seen := map[string]bool{}
	byType := map[string]*auditRecord{}
	for i := range recs {
		r := &recs[i]
		if !seen[r.typ] {
			seen[r.typ] = true
			types = append(types, r.typ)
			byType[r.typ] = r
		}
	}
	// Główny rekord: pierwszy niepomocniczy (CONFIG_CHANGE, AVC…), a gdy
	// są same pomocnicze – SYSCALL.
	primary := ""
	for _, t := range types {
		if !auditAux[t] {
			primary = t
			break
		}
	}
	if primary == "" {
		primary = recs[0].typ
		if byType["SYSCALL"] != nil {
			primary = "SYSCALL"
		}
	}

	// Pola rekordów: najpierw główny, potem pozostałe (pierwsze wystąpienie).
	// PATH i EXECVE osobno (powtarzane nazwy).
	put := func(k, v string) {
		if _, ok := out[k]; !ok && v != "" {
			out[k] = v
		}
	}
	order := []*auditRecord{byType[primary]}
	for i := range recs {
		if &recs[i] != byType[primary] {
			order = append(order, &recs[i])
		}
	}
	if ex := byType["EXECVE"]; ex != nil {
		for k, v := range ex.kv {
			out[k] = v // argumenty a0…aN zamiast surowych argumentów SYSCALL
		}
	}
	for _, r := range order {
		if r.typ == "PATH" || r.typ == "EXECVE" {
			continue
		}
		for k, v := range r.kv {
			put(k, v)
		}
		for k, v := range r.ext {
			put(k, v)
		}
	}
	if node != "" {
		put("node", node)
	}

	typ := primary
	if byType["EXECVE"] != nil {
		typ = "EXECVE"
	}
	out["type"] = typ
	out["audit.types"] = strings.Join(types, ",")
	out["audit.id"] = sec + "." + ms + ":" + serial
	if s, err := strconv.ParseInt(sec, 10, 64); err == nil {
		msec, _ := strconv.ParseInt((ms + "000")[:3], 10, 64)
		out["audit.ms"] = strconv.FormatInt(s*1000+msec, 10)
	}
	if k := out["key"]; k != "" {
		k, _, _ = strings.Cut(k, "\x01") // kilka kluczy reguły
		if k == "(null)" {
			delete(out, "key")
		} else {
			out["key"] = k
		}
	}

	// Akcja i wynik.
	action := auditActions[primary]
	switch {
	case typ == "EXECVE":
		action = "process-start"
	case primary == "AVC" || primary == "USER_AVC" || strings.HasPrefix(primary, "APPARMOR_"):
		action = "access-allowed"
		if strings.Contains(byType[primary].text, "denied") || primary == "APPARMOR_DENIED" {
			action = "access-denied"
		}
	case action == "" && strings.HasPrefix(primary, "ANOM_"):
		action = "anomaly"
	case action == "":
		action = strings.ReplaceAll(strings.ToLower(primary), "_", "-")
	}
	out["action"] = action
	switch strings.ToLower(firstOf(out["res"], out["success"], out["result"])) {
	case "success", "yes", "1":
		out["outcome"] = "success"
	case "failed", "failure", "no", "0":
		out["outcome"] = "failure"
	}
	if action == "access-denied" {
		out["outcome"] = "failure"
	}

	// Konta: kto (AUID) i na które konto (acct).
	login := auditUser(out, "AUID", "auid")
	switch {
	case targetTypes[primary]:
		put("target_user", firstOf(out["acct"], out["ID"]))
		put("user", login)
	case primary == "USER_LOGIN" || primary == "USER_AUTH" || primary == "USER_ACCT" || primary == "USER_ERR":
		put("user", firstOf(out["acct"], out["ID"], login))
	default:
		put("user", firstOf(login, auditUser(out, "UID", "uid"), out["acct"]))
	}
	if out["user"] == "?" {
		delete(out, "user")
	}

	// Polecenie, plik, adresy.
	if ex := byType["EXECVE"]; ex != nil {
		out["cmdline"] = execveCmdline(ex.kv)
	} else if p := out["proctitle"]; p != "" {
		out["cmdline"] = strings.TrimSpace(strings.ReplaceAll(p, "\x00", " "))
	}
	if typ == "EXECVE" {
		// Nazwy pól Sigmy (category process_creation).
		put("Image", out["exe"])
		put("CommandLine", out["cmdline"])
		put("CurrentDirectory", out["cwd"])
		put("User", auditUser(out, "UID", "uid"))
		put("ProcessId", out["pid"])
		put("ParentProcessId", out["ppid"])
	}
	if exe := out["exe"]; exe != "" && out["comm"] == "" {
		out["comm"] = path.Base(exe)
	}
	for i := range recs {
		r := &recs[i]
		if r.typ != "PATH" || r.kv["nametype"] == "PARENT" {
			continue
		}
		name := r.kv["name"]
		if name == "" || name == "(null)" {
			continue
		}
		if !strings.HasPrefix(name, "/") && out["cwd"] != "" {
			name = path.Join(out["cwd"], name)
		}
		put("file.path", name)
		put("name", r.kv["name"])
		put("nametype", r.kv["nametype"])
		break
	}
	if a, err := netip.ParseAddr(strings.TrimPrefix(out["addr"], "::ffff:")); err == nil && !a.IsUnspecified() {
		out["src_ip"] = a.Unmap().String()
	}
	if ip, port := sockaddr(out["saddr"]); ip != "" {
		out["dest_ip"], out["dest_port"] = ip, port
	}
	out["message"] = auditSummary(typ, out)
	return nil
}

// auditKV rozbiera pola rekordu: wartości w "…", '…' (msg='…' z polami
// programu – dołączane do tych samych pól) albo bez cudzysłowu (hex dla
// pól tekstowych).
func auditKV(s string, out map[string]string) {
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			continue
		}
		key := s[start:i]
		i++
		var val string
		quoted := false
		switch {
		case i < len(s) && (s[i] == '"' || s[i] == '\''):
			q := s[i]
			end := strings.IndexByte(s[i+1:], q)
			if end < 0 {
				val, i = s[i+1:], len(s)
			} else {
				val, i = s[i+1:i+1+end], i+end+2
			}
			quoted = true
		default:
			j := i
			for j < len(s) && s[j] != ' ' && s[j] != '\t' {
				j++
			}
			val, i = s[i:j], j
		}
		if key == "msg" && quoted {
			auditKV(val, out) // pola programu (PAM, sudo, useradd…)
			continue
		}
		if !quoted && val != "(null)" && val != "?" && (auditHexFields[key] || isArg(key)) {
			if b, err := hex.DecodeString(val); err == nil && len(val) >= 2 {
				val = string(b)
			}
		}
		if key != "" {
			if _, ok := out[key]; !ok {
				out[key] = val
			}
		}
	}
}

// isArg: argument EXECVE (a0, a12, a1[0]).
func isArg(k string) bool {
	if len(k) < 2 || k[0] != 'a' {
		return false
	}
	for _, c := range k[1:] {
		if (c < '0' || c > '9') && c != '[' && c != ']' {
			return false
		}
	}
	return true
}

// execveCmdline składa argumenty EXECVE (długie argumenty: aN_len, aN[0], aN[1]…).
func execveCmdline(kv map[string]string) string {
	n, err := strconv.Atoi(kv["argc"])
	if err != nil || n <= 0 || n > 4096 {
		n = 0
		for kv["a"+strconv.Itoa(n)] != "" || kv["a"+strconv.Itoa(n)+"_len"] != "" {
			n++
		}
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		a := "a" + strconv.Itoa(i)
		v, ok := kv[a]
		if !ok && kv[a+"_len"] != "" {
			var b strings.Builder
			for j := 0; ; j++ {
				part, ok := kv[a+"["+strconv.Itoa(j)+"]"]
				if !ok {
					break
				}
				b.WriteString(part)
			}
			v = b.String()
		}
		args = append(args, v)
	}
	return strings.Join(args, " ")
}

// auditUser: konto z pola ENRICHED (AUID="jan") albo numer (bez „unset”).
func auditUser(f map[string]string, enriched, raw string) string {
	if v := f[enriched]; v != "" && v != "unset" && v != "?" {
		return v
	}
	if v := f[raw]; v != "" && v != "4294967295" && v != "-1" && v != "unset" {
		return v
	}
	return ""
}

// sockaddr: adres i port z pola saddr (hex struct sockaddr; IPv4 i IPv6).
func sockaddr(h string) (string, string) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 8 {
		return "", ""
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(b[2:4])))
	switch binary.LittleEndian.Uint16(b[0:2]) {
	case 2: // AF_INET
		return netip.AddrFrom4([4]byte(b[4:8])).String(), port
	case 10: // AF_INET6
		if len(b) >= 24 {
			return netip.AddrFrom16([16]byte(b[8:24])).Unmap().String(), port
		}
	}
	return "", ""
}

func auditSummary(typ string, f map[string]string) string {
	parts := []string{typ}
	add := func(k, label string) {
		if v := f[k]; v != "" && v != "?" {
			parts = append(parts, label+"="+v)
		}
	}
	switch {
	case typ == "EXECVE":
		parts = append(parts, f["cmdline"])
	case f["op"] != "":
		add("op", "op")
		add("acct", "acct")
		add("cmd", "cmd")
		add("addr", "addr")
		add("res", "res")
	default:
		if f["SYSCALL"] != "" {
			add("SYSCALL", "syscall")
		} else {
			add("syscall", "syscall")
		}
		add("file.path", "path")
		add("comm", "comm")
		add("key", "key")
		add("success", "success")
	}
	s := strings.Join(parts, " ")
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
