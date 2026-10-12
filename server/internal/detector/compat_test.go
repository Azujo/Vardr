package detector

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/alerts"
	"siem/internal/contract"
	"siem/internal/decode"
	"siem/internal/detect"
	"siem/internal/identity"
	"siem/internal/model"
	"siem/server/internal/chwriter"
)

// Test zgodności silników (roadmapa, sekcja 19): ten sam zbiór zdarzeń
// i te same reguły dają te same trafienia w silniku w locie (Go) i w silniku
// zapytań (SQL na prawdziwym ClickHouse). Wymaga SIEM_TEST_CH_ADDR (pusty
// serwer testowy, np. usługa w CI); tworzy własną bazę compat_test.
//
//	SIEM_TEST_CH_ADDR=127.0.0.1:9000 [SIEM_TEST_CH_USER, SIEM_TEST_CH_PASSWORD]

const compatDDL = `CREATE TABLE compat_test.events
(
    timestamp            DateTime64(3, 'UTC'),
    ingested             DateTime64(3, 'UTC'),
    event_id             String,
    agent_id             LowCardinality(String),
    event_dataset        LowCardinality(String),
    event_code           UInt32,
    event_provider       LowCardinality(String),
    event_action         LowCardinality(String),
    event_outcome        LowCardinality(String),
    host_name            LowCardinality(String),
    user_name            String,
    user_domain          LowCardinality(String),
    source_ip            IPv6,
    process_name         String,
    process_command_line String,
    message              String,
    fields               Map(LowCardinality(String), String),
    raw                  String,
    truncated            Bool,
    parser_version       LowCardinality(String),
    time_quality         LowCardinality(String),
    user_identity        LowCardinality(String) DEFAULT '',
    INDEX idx_ingested ingested TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree(ingested)
PARTITION BY toYYYYMMDD(ingested)
ORDER BY (event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)`

var compatT0 = time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)

type corpus struct {
	events []model.Event
	n      int
}

// add dodaje zdarzenie; at – czas wystąpienia, late – opóźnienie przyjęcia.
func (c *corpus) add(channel string, code uint32, host string, at, late time.Duration, f map[string]string) *model.Event {
	c.n++
	fields := map[string]string{"winlog.channel": channel}
	for k, v := range f {
		fields[k] = v
	}
	e := model.Event{ID: fmt.Sprintf("%s:%s:g0:%d", host, channel, c.n), AgentID: "agt-" + host, Code: code,
		HostName: host, Timestamp: compatT0.Add(at), Ingested: compatT0.Add(at + late + 2*time.Second),
		Dataset: "windows." + strings.ToLower(strings.ReplaceAll(channel, "/", ".")), Fields: fields,
		Parser: model.ParserVersion}
	e.UserName = f["TargetUserName"]
	e.UserDomain = f["TargetDomainName"]
	e.Identity = identity.New(identity.Config{}).Resolve(e.UserName, e.UserDomain)
	if ip := strings.TrimPrefix(f["IpAddress"], "::ffff:"); ip != "" && ip != "-" {
		e.SourceIP = ip
	}
	e.CommandLine = f["CommandLine"]
	c.events = append(c.events, e)
	return &c.events[len(c.events)-1]
}

func buildCorpus() []model.Event {
	c := &corpus{}
	sec, sys := "Security", "System"
	sysmon, ps := "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"
	logon := func(at, late time.Duration, user, ip, host string) {
		c.add(sec, 4625, host, at, late, map[string]string{"TargetUserName": user, "TargetDomainName": "LAB",
			"IpAddress": ip, "LogonType": "3", "Status": "0xc000006d"})
	}
	// Brute force: 12 prób w 3 min, kontynuacja po 40 i 70 min (łańcuch),
	// pojedyncza próba po 4 h (poza łańcuchem). Część przyjęta z opóźnieniem.
	for i := range 12 {
		late := time.Duration(0)
		if i%4 == 0 {
			late = 30 * time.Minute // z bufora agenta
		}
		logon(time.Duration(i)*15*time.Second, late, "jan", "10.0.0.5", "dc01")
	}
	logon(40*time.Minute, 0, "JAN", "10.0.0.6", "pc02")
	logon(70*time.Minute, 0, "jan", "10.0.0.6", "pc02")
	logon(4*time.Hour, 0, "jan", "10.0.0.6", "pc02")
	// Poniżej progu: 8 prób w 5 min, potem 2 po 20 min.
	for i := range 8 {
		logon(10*time.Minute+time.Duration(i)*30*time.Second, 0, "ewa", "10.0.0.8", "dc01")
	}
	logon(30*time.Minute, 0, "ewa", "10.0.0.8", "dc01")
	logon(31*time.Minute, 0, "ewa", "10.0.0.8", "dc01")
	// Password spraying: 6 kont z 10.0.0.9 w 8 min (+ powtórzenia), konta lokalne bez adresu.
	for i, u := range []string{"anna", "piotr", "kasia", "anna", "tomek", "ola", "marek", "piotr"} {
		logon(2*time.Hour+time.Duration(i)*time.Minute, time.Duration(i%3)*time.Hour, u, "10.0.0.9", "dc01")
	}
	for i, u := range []string{"a1", "a2", "a3", "a4", "a5", "a6"} {
		logon(2*time.Hour+time.Duration(i)*time.Second, 0, u, "-", fmt.Sprintf("pc%d", i))
	}
	// Kerberos 0x18 ×10 w 4 min (adres ::ffff:), 0x12 ×5 (inny kod – nie liczy się).
	for i := range 10 {
		c.add(sec, 4771, "dc01", 3*time.Hour+time.Duration(i)*20*time.Second, 0,
			map[string]string{"TargetUserName": "adam", "IpAddress": "::ffff:10.0.0.7", "Status": "0x18"})
	}
	for i := range 5 {
		c.add(sec, 4771, "dc01", 3*time.Hour+time.Duration(i)*time.Second, 0,
			map[string]string{"TargetUserName": "basia", "IpAddress": "::ffff:10.0.0.7", "Status": "0x12"})
	}
	// Tworzenie procesów: Security 4688 i Sysmon 1.
	proc := func(ch string, code uint32, at time.Duration, img, cmd, parent string) {
		f := map[string]string{"CommandLine": cmd}
		if code == 1 {
			f["Image"], f["ParentImage"] = img, parent
		} else {
			f["NewProcessName"], f["ParentProcessName"] = img, parent
		}
		c.add(ch, code, "pc01", at, 0, f)
	}
	ps1 := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	proc(sec, 4688, time.Hour, ps1, `powershell -NoP -enc SQBFAFgA`, `C:\Windows\explorer.exe`)
	proc(sysmon, 1, time.Hour, `C:\Program Files\PowerShell\7\pwsh.exe`, `pwsh /e SQBFAFgA`, `C:\Office\winword.exe`)
	proc(sec, 4688, time.Hour, ps1, `powershell -File x.ps1 -Encoding utf8`, `C:\Windows\explorer.exe`)
	proc(sec, 4688, time.Hour, `C:\Windows\System32\CMD.EXE`, `cmd.exe /c whoami /all`, `C:\Tools\x.exe`)
	proc(sysmon, 1, time.Hour, `C:\Windows\System32\cmd.exe`, `cmd /C WHOAMI`, `C:\Program Files\App\a.exe`)
	proc(sec, 4688, time.Hour, `C:\Windows\System32\net.exe`, `net user hacker P@ss /add`, `C:\Tools\x.exe`)
	proc(sec, 4688, time.Hour, `C:\Tools\a.exe`, `a.exe lit*eral`, `C:\Tools\x.exe`)
	proc(sec, 4688, time.Hour, `C:\Tools\a.exe`, `a.exe litXeral`, `C:\Tools\x.exe`)
	proc(sysmon, 1, time.Hour, `C:\Windows\cmd.exe.bak`, `cmd /c whoami`, `C:\Windows\explorer.exe`)
	// PowerShell 4104.
	c.add(ps, 4104, "pc01", time.Hour, 0, map[string]string{"ScriptBlockText": "$k=[Kernel32]::VirtualAlloc(0,4096)"})
	c.add(ps, 4104, "pc01", time.Hour, 0, map[string]string{"ScriptBlockText": "(New-Object Net.WebClient).DownloadFile('a','b')"})
	c.add(ps, 4104, "pc01", time.Hour, 0, map[string]string{"ScriptBlockText": "(New-Object Net.WebClient).DownloadString('a')"})
	// Usługi 7045.
	c.add(sys, 7045, "srv01", time.Hour, 0, map[string]string{"ServiceName": "upd", "ImagePath": `C:\Users\jan\AppData\Local\Temp\u.exe`})
	c.add(sys, 7045, "srv01", time.Hour, 0, map[string]string{"ServiceName": "ok", "ImagePath": `"C:\Program Files\Vendor\svc.exe"`})
	// Grupy uprzywilejowane, czyszczenie dziennika, nowe konto.
	c.add(sec, 4732, "dc01", time.Hour, 0, map[string]string{"TargetSid": "S-1-5-32-551", "TargetUserName": "Backup Operators"})
	c.add(sec, 4728, "dc01", time.Hour, 0, map[string]string{"TargetSid": "S-1-5-21-1-2-3-512", "TargetUserName": "Domain Admins"})
	c.add(sec, 4728, "dc01", time.Hour, 0, map[string]string{"TargetSid": "S-1-5-21-1-2-3-1105", "TargetUserName": "Kadry"})
	c.add(sec, 1102, "dc01", time.Hour, 0, map[string]string{"SubjectUserName": "admin"})
	c.add(sec, 4720, "dc01", time.Hour, 0, map[string]string{"TargetUserName": "nowy"})
	c.add(sys, 104, "pc01", time.Hour, 0, map[string]string{"SubjectUserName": "admin"}).Provider = "Microsoft-Windows-Eventlog"
	c.add(sys, 104, "pc01", time.Hour, 0, map[string]string{"SubjectUserName": "admin"}).Provider = "Inny-Dostawca"
	c.add(sys, 7036, "dc01", time.Hour, 0, map[string]string{"param1": "SIEM Agent", "param2": "stopped"})
	c.add(sys, 7036, "dc01", time.Hour, 0, map[string]string{"param1": "SIEM Agent", "param2": "running"})
	c.add(sys, 7036, "pc01", time.Hour, 0, map[string]string{"param1": "Sysmon64", "param2": "Zatrzymany"})
	c.add(sys, 7034, "pc01", time.Hour, 0, map[string]string{"param1": "Sysmon64", "param2": "1"})
	c.add(sys, 7036, "pc01", time.Hour, 0, map[string]string{"param1": "Spooler", "param2": "stopped"})
	// Konstrukcje reguł testowych: regex, adresy, null/exists, wielkość liter, Unicode, słowa kluczowe.
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "ADM42", "IpAddress": "192.168.88.200"})
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "adm4x", "IpAddress": "192.168.88.100",
		"LogonProcessName": "NtLmSsp", "WorkstationName": "PC03"})
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "x", "IpAddress": "::ffff:10.0.0.77",
		"LogonProcessName": "", "WorkstationName": "PC03", "ElevatedToken": "%%1842"})
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "y", "IpAddress": "fd12::5", "LogonProcessName": "Kerberos"})
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "z", "IpAddress": "-", "LogonProcessName": "Kerberos"})
	c.add(sec, 4624, "pc03", time.Hour, 0, map[string]string{"TargetUserName": "ŁUKASZ", "LogonProcessName": "Kerberos"})
	c.add(sec, 4740, "dc01", time.Hour, 0, map[string]string{"TargetUserName": "Żółwik"})
	c.add(sec, 4767, "dc01", time.Hour, 0, nil)
	e := c.add(sec, 4688, "pc01", time.Hour, 0, map[string]string{"CommandLine": "x.exe"})
	e.Raw = "<Event><Data>privilege::debug sekurlsa::logonpasswords</Data></Event>"
	e = c.add(sec, 4688, "pc01", time.Hour, 0, map[string]string{"CommandLine": "y.exe"})
	e.Message = "Uruchomiono MimiKatz"
	c.network()
	return c.events
}

// network dodaje zdarzenia urządzeń sieciowych przez prawdziwe dekodery
// syslog (pola docelowe, zbiór danych, czas z treści albo nagłówka).
func (c *corpus) network() {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	ds, err := decode.Builtin(loc)
	if err != nil {
		panic(err)
	}
	set := decode.NewSet(ds)
	add := func(at, late time.Duration, line string) {
		c.n++
		ts := compatT0.Add(at).In(loc)
		raw := strings.NewReplacer("{bsd}", ts.Format(time.Stamp), "{date}", ts.Format("2006-01-02"),
			"{time}", ts.Format("15:04:05")).Replace(line)
		src := "syslog:udp"
		if strings.HasPrefix(raw, "{") {
			src = "entra:signin"
		}
		e, err := decode.Event(contract.Event{ID: fmt.Sprintf("collector:syslog:g0:%d", c.n), Source: src, Raw: raw, Peer: "192.168.88.1"},
			"agt-collector", compatT0.Add(at+late+2*time.Second), set, loc)
		if err != nil {
			panic(err)
		}
		e.Identity = identity.New(identity.Config{}).Resolve(e.UserName, e.UserDomain)
		c.events = append(c.events, e)
	}
	mt := func(at, late time.Duration, msg string) { add(at, late, "<131>{bsd} MikroTik "+msg) }
	// MikroTik: 6 nieudanych z jednego adresu w 2 min (część z opóźnieniem), 4 z innego (poniżej progu),
	// udane logowania się nie liczą; RouterOS 6 z tematami w nagłówku.
	for i := range 6 {
		mt(5*time.Hour+time.Duration(i)*20*time.Second, time.Duration(i%2)*10*time.Minute,
			"login failure for user admin from 203.0.113.9 via winbox")
	}
	for i := range 4 {
		mt(5*time.Hour+time.Duration(i)*time.Minute, 0, "login failure for user admin from 192.168.88.50 via ssh")
	}
	for i := range 5 {
		mt(5*time.Hour+time.Duration(i)*time.Second, 0, "user admin logged in from 192.168.88.10 via winbox")
	}
	for i := range 5 {
		add(6*time.Hour+time.Duration(i)*30*time.Second, 0,
			"<86>{bsd} gw-old system,error,critical login failure for user root from 198.51.100.3 via ssh")
	}
	// FortiGate: VPN 11 prób z jednego adresu (różne konta), 9 z innego; administrator 5 prób.
	vpn := `<189>date={date} time={time} devname="FGT-HQ" tz="+0200" logid="0101039426" type="event" subtype="vpn" ` +
		`action="ssl-login-fail" remip=%s user="%s" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"`
	for i := range 11 {
		add(7*time.Hour+time.Duration(i)*15*time.Second, 0, fmt.Sprintf(vpn, "203.0.113.45", []string{"jan", "ewa", "adam"}[i%3]))
	}
	for i := range 9 {
		add(7*time.Hour+time.Duration(i)*15*time.Second, 0, fmt.Sprintf(vpn, "203.0.113.46", "jan"))
	}
	for i := range 5 {
		add(8*time.Hour+time.Duration(i)*time.Minute, 0, `<185>date={date} time={time} devname="FGT-HQ" tz="+0200" `+
			`logid="0100032002" type="event" subtype="system" user="admin" srcip=198.51.100.7 action="login" status="failed"`)
	}
	// Spraying z jednego adresu rozłożony na źródła (etap 7d): 2 konta w AD,
	// 2 w Entra ID (jedno to ta sama osoba co w AD – nie liczy się podwójnie),
	// 1 na VPN – razem 5 różnych osób w 10 min. Drugi adres: 4 osoby (poniżej progu).
	spray := "198.51.100.50"
	for i, u := range []string{"marta", "tomasz"} {
		c.add("Security", 4625, "dc01", 9*time.Hour+time.Duration(i)*time.Minute, 0,
			map[string]string{"TargetUserName": u, "TargetDomainName": "LAB", "IpAddress": spray})
	}
	entra := `{"id":"sp-%d","createdDateTime":"%s","userPrincipalName":"%s@lab.pl","ipAddress":"%s","appDisplayName":"Office 365",` +
		`"clientAppUsed":"IMAP4","status":{"errorCode":50126,"failureReason":"Invalid password"},"location":{"countryOrRegion":"NL"}}`
	for i, u := range []string{"Tomasz", "julia", "kamil"} {
		ts := compatT0.Add(9*time.Hour + time.Duration(3+i)*time.Minute)
		add(9*time.Hour+time.Duration(3+i)*time.Minute, 0, fmt.Sprintf(entra, i, ts.Format(time.RFC3339), u, spray))
	}
	add(9*time.Hour+7*time.Minute, 0, fmt.Sprintf(vpn, spray, "piotr.vpn"))
	for i, u := range []string{"a1x", "a2x", "a3x", "a4x"} {
		ts := compatT0.Add(9*time.Hour + time.Duration(i)*time.Minute)
		add(9*time.Hour+time.Duration(i)*time.Minute, 0, fmt.Sprintf(entra, 10+i, ts.Format(time.RFC3339), u, "198.51.100.51"))
	}
}

type hitKey struct{ rule, event, group string }

func hitSet(hits []alerts.Hit) map[hitKey]bool {
	out := map[hitKey]bool{}
	for _, h := range hits {
		out[hitKey{h.RuleID, h.EventID, h.GroupKey}] = true
	}
	return out
}

func diffSets(t *testing.T, what string, stream, index map[hitKey]bool) {
	t.Helper()
	var only []string
	for k := range stream {
		if !index[k] {
			only = append(only, "tylko w locie: "+fmt.Sprint(k))
		}
	}
	for k := range index {
		if !stream[k] {
			only = append(only, "tylko w zapytaniach: "+fmt.Sprint(k))
		}
	}
	sort.Strings(only)
	if len(only) > 0 {
		t.Errorf("%s – różnice silników:\n%s", what, strings.Join(only, "\n"))
	}
}

func TestEngineCompatibility(t *testing.T) {
	addr := os.Getenv("SIEM_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("brak SIEM_TEST_CH_ADDR – pomijam test zgodności z ClickHouse")
	}
	ctx := context.Background()
	user := os.Getenv("SIEM_TEST_CH_USER")
	if user == "" {
		user = "default"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{Addr: []string{addr},
		Auth: clickhouse.Auth{Username: user, Password: os.Getenv("SIEM_TEST_CH_PASSWORD")}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, q := range []string{"DROP DATABASE IF EXISTS compat_test", "CREATE DATABASE compat_test", compatDDL} {
		if err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	events := buildCorpus()
	w := &chwriter.Writer{Conn: conn, Table: "compat_test.events"}
	// Zapis w dwóch paczkach, druga powtarza część pierwszej (duplikaty jak przy ponownym dostarczeniu).
	if err := w.InsertEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	if err := w.InsertEvents(ctx, events[:20]); err != nil {
		t.Fatal(err)
	}

	repo, errs, err := detect.LoadDir("../../../rules")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	extra, errs, err := detect.LoadDir("testdata/compat")
	if err != nil || len(errs) > 0 {
		t.Fatal(err, errs)
	}
	rules := append(repo, extra...)

	// 1. Dopasowanie pojedynczych zdarzeń: Go (Match) i SQL (SQL) dla każdej reguły.
	for _, r := range rules {
		var want []string
		for i := range events {
			if r.Match(detect.Event{Event: &events[i]}) {
				want = append(want, events[i].ID)
			}
		}
		rows, err := conn.Query(ctx, "SELECT DISTINCT event_id FROM compat_test.events WHERE "+r.SQL()+" ORDER BY event_id")
		if err != nil {
			t.Fatalf("%s: SQL: %v\n%s", r.ID, err, r.SQL())
		}
		var got []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			got = append(got, id)
		}
		rows.Close()
		sort.Strings(want)
		if !slices.Equal(want, got) {
			t.Errorf("%s (%s): Go %v\nSQL %v", r.Title, r.ID, want, got)
		}
		if len(want) == 0 {
			t.Errorf("%s (%s): korpus nie ma zdarzenia pasującego do reguły", r.Title, r.ID)
		}
	}

	// 2. Trafienia obu silników (z progami): w locie – zdarzenia w losowej
	// kolejności napływu, małymi paczkami; zapytania – trzy przebiegi po
	// czasie przyjęcia.
	for seed := range uint64(3) {
		eng := NewEngine()
		eng.SetRules(rules)
		// Napływ wg czasu przyjęcia, przemieszany w obrębie 10 zdarzeń (równoległe
		// paczki agentów). Spóźnienie ponad ThresholdLateness wobec najnowszego
		// zdarzenia klucza to udokumentowana granica silnika w locie – korpus jej
		// nie przekracza.
		order := slices.Clone(events)
		sort.SliceStable(order, func(i, j int) bool { return order[i].Ingested.Before(order[j].Ingested) })
		rnd := rand.New(rand.NewPCG(seed, 42))
		for i := 0; i < len(order); i += 10 {
			part := order[i:min(i+10, len(order))]
			rnd.Shuffle(len(part), func(a, b int) { part[a], part[b] = part[b], part[a] })
		}
		var stream []alerts.Hit
		for i := 0; i < len(order); i += 7 {
			h, _ := eng.Evaluate(&model.Batch{Events: order[i:min(i+7, len(order))]})
			stream = append(stream, h...)
		}
		// Ponowne dostarczenie paczki – bez nowych trafień.
		if h, _ := eng.Evaluate(&model.Batch{Events: order[:7]}); len(hitSetOnlyThreshold(h)) > 0 {
			t.Errorf("ponowne dostarczenie dało trafienia progowe: %v", h)
		}
		idx := &Index{Conn: conn, Table: "compat_test.events"}
		var index []alerts.Hit
		cuts := []time.Time{compatT0.Add(-time.Hour), compatT0.Add(90 * time.Minute), compatT0.Add(3 * time.Hour),
			compatT0.Add(10 * time.Hour)}
		for i := 0; i+1 < len(cuts); i++ {
			res, err := idx.Run(ctx, IndexRules(rules), Cursor{Ingested: cuts[i]}, cuts[i+1])
			if err != nil {
				t.Fatal(err)
			}
			index = append(index, res.Hits...)
		}
		if seed == 0 {
			t.Logf("trafienia: w locie %d, zapytania %d (unikalne %d / %d)", len(stream), len(index),
				len(hitSet(stream)), len(hitSet(index)))
		}
		diffSets(t, fmt.Sprintf("kolejność %d", seed), hitSet(stream), hitSet(index))
		if seed == 0 {
			// Mały limit wierszy: przebieg kontynuowany kursorem (także w obrębie
			// tej samej chwili przyjęcia) daje te same trafienia.
			small := &Index{Conn: conn, Table: "compat_test.events", MaxRows: 7}
			var paged []alerts.Hit
			from, to := Cursor{Ingested: cuts[0]}, cuts[len(cuts)-1]
			for runs := 0; ; runs++ {
				res, err := small.Run(ctx, IndexRules(rules), from, to)
				if err != nil {
					t.Fatal(err)
				}
				paged = append(paged, res.Hits...)
				if !res.More {
					break
				}
				if runs > 1000 || !(res.Next.Ingested.After(from.Ingested) || res.Next.EventID > from.EventID) {
					t.Fatalf("kursor nie posuwa się: %+v → %+v", from, res.Next)
				}
				from = res.Next
			}
			diffSets(t, "przebiegi z limitem wierszy", hitSet(stream), hitSet(paged))
		}
	}
}

func hitSetOnlyThreshold(hits []alerts.Hit) []alerts.Hit {
	var out []alerts.Hit
	for _, h := range hits {
		if strings.HasPrefix(h.Summary, "próg:") {
			out = append(out, h)
		}
	}
	return out
}

// Semantyka progów niezależna od kolejności: łańcuch po Suppress i okno.
func TestThresholdMarksChain(t *testing.T) {
	th := &detect.Threshold{Count: 3, Window: detect.Duration(time.Minute)}
	at := func(sec ...int) []*entry {
		var es []*entry
		for i, s := range sec {
			es = append(es, &entry{Observation: alerts.Observation{EventID: fmt.Sprint(i),
				EventTime: compatT0.Add(time.Duration(s) * time.Second)}})
		}
		return es
	}
	// 3 w 60 s → okno; +500 s (≤ 600 s od poprzedniego) → łańcuch; +2000 s → osobno; −300 s przed → łańcuch wstecz.
	es := at(-300, 0, 30, 60, 560, 2560)
	marks, wins, _ := thresholdMarks(es, th, 10*time.Minute)
	if want := []bool{true, true, true, true, true, false}; !slices.Equal(marks, want) || len(wins) != 1 {
		t.Fatalf("znaczniki %v (okna %v), oczekiwano %v", marks, wins, want)
	}
	if c := components(es, marks, 10*time.Minute); len(c) != 1 || c[0] != (detect.Span{From: 0, To: 5}) {
		t.Fatalf("serie: %v", c)
	}
	if marks, _, _ := thresholdMarks(at(0, 30, 61), th, 10*time.Minute); slices.Contains(marks, true) {
		t.Fatalf("3 zdarzenia w 61 s nie mieszczą się w oknie 60 s: %v", marks)
	}
	// Zdarzenie już w alercie (okno wypadło z pamięci) zaczepia łańcuch.
	es = at(0, 500, 3000)
	es[0].emitted = true
	if marks, _, _ := thresholdMarks(es, th, 10*time.Minute); !slices.Equal(marks, []bool{true, true, false}) {
		t.Fatalf("łańcuch od zdarzenia w alercie: %v", marks)
	}
}
